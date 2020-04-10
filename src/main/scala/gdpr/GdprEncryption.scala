package gdpr

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}

import akka.actor.Cancellable
import akka.actor.typed._
import akka.actor.typed.scaladsl.{ActorContext, Behaviors, StashBuffer}
import com.github.j5ik2o.reactive.aws.kms.KmsAsyncClient
import com.typesafe.config.Config
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.model.{
  DataKeySpec,
  DecryptRequest,
  GenerateDataKeyRequest
}
import software.amazon.awssdk.services.kms.{
  KmsAsyncClient => JavaKmsAsyncClient
}

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success}
import scala.jdk.CollectionConverters._

object EncryptionService {

  sealed trait Command
  sealed trait CommandReply
  sealed trait HashReply extends Command {
    type R <: CommandReply
    def replyTo: ActorRef[R]
  }
  final case class DataKey(secretKeySpec: SecretKeySpec,
                           ciphertextBlob: Array[Byte],
                           dataSubjectId: String)
      extends Command
  final case class DecryptInProgress(secretKeySpec: SecretKeySpec,
                                     encryptedBody: Array[Byte],
                                     iv: Array[Byte],
                                     replyTo: ActorRef[DecryptReply])
      extends Command
  final case class Encrypt(bytes: Array[Byte],
                           dataSubjectId: String,
                           replyTo: ActorRef[EncryptReply])
      extends HashReply {
    override type R = EncryptReply
  }
  sealed trait EncryptReply extends CommandReply
  final case class EncryptSucceeded(bytes: Array[Byte]) extends EncryptReply
  final case class EncryptFailed(message: String) extends EncryptReply

  final case class Decrypt(bytes: Array[Byte],
                           subjectId: String,
                           replyTo: ActorRef[DecryptReply])
      extends HashReply {
    override type R = DecryptReply
  }
  sealed trait DecryptReply extends CommandReply
  final case class DecryptSucceeded(bytes: Array[Byte]) extends DecryptReply
  final case class DecryptFailed(message: String) extends DecryptReply

  private def generateDataKey(ctx: ActorContext[Command],
                              asyncClient: KmsAsyncClient)(
    keyArn: String,
    dataSubjectId: String
  )(implicit ec: ExecutionContext): Future[(SecretKeySpec, SdkBytes)] = {
    asyncClient
      .generateDataKey(
        GenerateDataKeyRequest
          .builder()
          .keyId(keyArn)
          .keySpec(DataKeySpec.AES_256)
          .encryptionContext(Map("dataSubjectId" -> dataSubjectId).asJava)
          .build()
      )
      .map { response =>
        val secretKeySpec =
          new SecretKeySpec(response.plaintext().asByteArray(), "AES")
        val encryptedKey = response.ciphertextBlob()
        (secretKeySpec, encryptedKey)
      }
  }

  private def combine(iv: Array[Byte],
                      ciphertextBlob: Array[Byte],
                      encrypted: Array[Byte]): Array[Byte] = {
    var baos: ByteArrayOutputStream = null
    try {
      baos = new ByteArrayOutputStream()
      baos.write(iv.length)
      baos.write(iv)
      baos.write(ciphertextBlob.length)
      baos.write(ciphertextBlob)
      baos.write(encrypted.length)
      baos.write(encrypted)
      baos.toByteArray
    } finally {
      if (baos != null)
        baos.close()
    }
  }

  private def divide(
    payload: Array[Byte]
  ): (Array[Byte], Array[Byte], Array[Byte]) = {
    var bais: ByteArrayInputStream = null
    try {
      bais = new ByteArrayInputStream(payload)
      val ivSize = bais.read()
      val iv = Array.ofDim[Byte](ivSize)
      bais.read(iv)
      val encryptedKeySize = bais.read()
      val encryptedKey = Array.ofDim[Byte](encryptedKeySize)
      bais.read(encryptedKey)
      val encryptedBodySize = bais.read()
      val encryptedBody = Array.ofDim[Byte](encryptedBodySize)
      bais.read(encryptedBody)
      (iv, encryptedKey, encryptedBody)
    } finally {
      if (bais != null)
        bais.close()
    }
  }

  private def created(
    buffer: StashBuffer[Command],
    asyncClient: KmsAsyncClient,
    keyArn: String,
    dataSubjectId: String
  )(dataKey: DataKey)(implicit ec: ExecutionContext): Behavior[Command] = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    Behaviors.receive[Command] { (ctx, msg) =>
      msg match {
        case msg: DataKey =>
          buffer.unstashAll(
            created(buffer, asyncClient, keyArn, msg.dataSubjectId)(msg)
          )
        case Encrypt(bytes, dsi, replyTo) =>
          if (dsi != dataSubjectId) {
            ctx.pipeToSelf(generateDataKey(ctx, asyncClient)(keyArn, dsi)) {
              case Success((spec, bytes)) =>
                ctx.log.info(s"dataKey = $spec, dataSubjectId = $dsi")
                DataKey(spec, bytes.asByteArray(), dsi)
              case Failure(exception) => throw exception
            }
            buffer.stash(msg)
          } else {
            ctx.log.info("cipher.init")
            cipher.init(
              Cipher.ENCRYPT_MODE,
              dataKey.secretKeySpec,
              new IvParameterSpec("abcdefghijklmnop".getBytes)
            )
            ctx.log.info("cipher.doFinal")
            val encryptedBody = cipher.doFinal(bytes)
            ctx.log.info("combine " + cipher.getAlgorithm)
            val encrypted =
              combine(cipher.getIV, dataKey.ciphertextBlob, encryptedBody)
            ctx.log.info("replyTo ! EncryptSucceeded")
            replyTo ! EncryptSucceeded(encrypted)
          }
          Behaviors.same
        case Decrypt(bytes, dsi, replyTo) if dsi == dataSubjectId =>
          ctx.log.info("divide")
          val (iv, encryptedKey, encryptedBody) = divide(bytes)
          ctx.log.info("decryptDataKey")
          val future =
            decryptDataKey(asyncClient, keyArn, dsi, encryptedKey)
          ctx.pipeToSelf[SecretKeySpec](future) {
            case Success(secretKeySpec) =>
              DecryptInProgress(secretKeySpec, encryptedBody, iv, replyTo)
            case Failure(exception) => throw exception
          }
          Behaviors.same
        case DecryptInProgress(secretKeySpec, encryptedBody, iv, replyTo) =>
          ctx.log.info("cipher.init")
          cipher.init(
            Cipher.DECRYPT_MODE,
            secretKeySpec,
            new IvParameterSpec(iv)
          )
          ctx.log.info("cipher.doFinal")
          val decrypted = cipher.doFinal(encryptedBody)
          ctx.log.info("replyTo ! DecryptSucceeded")
          replyTo ! DecryptSucceeded(decrypted)
          Behaviors.same
        case _ =>
          Behaviors.ignore
      }
    }
  }

  private def decryptDataKey(
    asyncClient: KmsAsyncClient,
    keyArn: String,
    dataSubjectId: String,
    encryptedKey: Array[Byte]
  )(implicit ec: ExecutionContext): Future[SecretKeySpec] = {
    val request = DecryptRequest
      .builder()
      .keyId(keyArn)
      .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey))
      .encryptionContext(Map("dataSubjectId" -> dataSubjectId).asJava)
      .build()
    val future = asyncClient
      .decrypt(request)
      .map { response =>
        val rawKey = response.plaintext().asByteArray()
        new SecretKeySpec(rawKey, "AES")
      }
    future
  }

  private def childBehavior(
    keyArn: String,
    awsCredentialsProvider: Option[AwsCredentialsProvider]
  ): Behavior[Command] =
    Behaviors.withStash(256) { buffer: StashBuffer[Command] =>
      Behaviors.setup { ctx =>
        import ctx.executionContext
        val javaAsyncClientBuilder = JavaKmsAsyncClient.builder()
        val javaAsyncClient = awsCredentialsProvider match {
          case None    => javaAsyncClientBuilder.build()
          case Some(c) => javaAsyncClientBuilder.credentialsProvider(c).build()
        }
        val kmsAsyncClient: KmsAsyncClient = KmsAsyncClient(javaAsyncClient)
        Behaviors.receiveMessage[Command] {
          case msg: DataKey =>
            buffer.unstashAll(
              created(buffer, kmsAsyncClient, keyArn, msg.dataSubjectId)(msg)
            )
          case msg: Encrypt =>
            val future =
              generateDataKey(ctx, kmsAsyncClient)(keyArn, msg.dataSubjectId)
            ctx.pipeToSelf(future) {
              case Success((spec, bytes)) =>
                ctx.log.info(
                  s"dataKey = $spec, dataSubjectId = ${msg.dataSubjectId}"
                )
                DataKey(spec, bytes.asByteArray(), msg.dataSubjectId)
              case Failure(exception) => throw exception
            }
            buffer.stash(msg)
            Behaviors.same
          case _ =>
            Behaviors.ignore
        }
      }
    }

  def behavior(
    keyArn: String,
    awsCredentialsProvider: Option[AwsCredentialsProvider]
  ): Behavior[Command] = Behaviors.setup { ctx =>
    import ctx.executionContext
    var cancel: Cancellable = null
    Behaviors
      .receiveMessage[Command] { msg =>
        ctx.child("child") match {
          case None =>
            val childRef =
              ctx
                .spawn(childBehavior(keyArn, awsCredentialsProvider), "child")
            cancel = ctx.system.scheduler
              .scheduleOnce(3 seconds, { () =>
                ctx.log.info("stop")
                ctx.stop(childRef)
              })
            ctx.log.info(s"forward: $msg")
            childRef ! msg
          case Some(c) =>
            c.asInstanceOf[ActorRef[Command]] ! msg
        }
        Behaviors.same
      }
      .receiveSignal {
        case (_, PostStop) =>
          cancel.cancel()
          Behaviors.same
      }
  }

}

class GdprEncryption(system: ActorSystem[_]) extends Extension {
  private val config: Config = system.settings.config

  val keyArn = config.getString("key-arn")

  private val javaAsyncClient = JavaKmsAsyncClient.builder().build()
  private val asyncClient: KmsAsyncClient = KmsAsyncClient(javaAsyncClient)

  private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

}

object GdprEncryption extends ExtensionId[GdprEncryption] {

  override def createExtension(system: ActorSystem[_]): GdprEncryption =
    GdprEncryption(system)

  def get(system: ActorSystem[_]): GdprEncryption = apply(system)

}
