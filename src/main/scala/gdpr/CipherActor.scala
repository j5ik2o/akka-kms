package gdpr

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.charset.StandardCharsets

import akka.actor.Cancellable
import akka.actor.typed.scaladsl.{ActorContext, Behaviors, StashBuffer}
import akka.actor.typed.{ActorRef, Behavior, PostStop}
import javax.crypto.spec.IvParameterSpec
import javax.crypto.{Cipher, SecretKey}

import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.util.{Failure, Random, Success}

object CipherActor {

  sealed trait Command
  sealed trait CommandReply
  sealed trait HashReply extends Command {
    type R <: CommandReply
    def replyTo: ActorRef[R]
  }
  private final case object GracefulStop extends Command
  private final case class DataKey(secretKeySpec: SecretKey,
                                   ciphertextBlob: Array[Byte],
                                   dataSubjectId: String)
      extends Command
  private final case class DecryptInProgress(secretKeySpec: SecretKey,
                                             encryptedBody: Array[Byte],
                                             iv: Array[Byte],
                                             replyTo: ActorRef[DecryptReply])
      extends Command
  // ---
  final case class Encrypt(bytes: Array[Byte],
                           dataSubjectId: String,
                           replyTo: ActorRef[EncryptReply])
      extends HashReply {
    override type R = EncryptReply
  }
  sealed trait EncryptReply extends CommandReply
  final case class EncryptSucceeded(bytes: Array[Byte]) extends EncryptReply
  final case class EncryptFailed(message: String) extends EncryptReply
  // ---
  final case class Decrypt(bytes: Array[Byte],
                           subjectId: String,
                           replyTo: ActorRef[DecryptReply])
      extends HashReply {
    override type R = DecryptReply
  }
  sealed trait DecryptReply extends CommandReply
  final case class DecryptSucceeded(bytes: Array[Byte]) extends DecryptReply
  final case class DecryptFailed(message: String) extends DecryptReply

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

  val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

  private def created(
    buffer: StashBuffer[Command],
    keyManagement: KeyManagement,
    dataKey: DataKey
  )(implicit ec: ExecutionContext): Behavior[Command] = {
    Behaviors
      .receive[Command] { (ctx, msg) =>
        msg match {
          case GracefulStop =>
            Behaviors.stopped
          case dataKey: DataKey =>
            buffer.unstashAll(created(buffer, keyManagement, dataKey))
          case m @ Encrypt(bytes, dsi, replyTo) =>
            if (dsi != dataKey.dataSubjectId) {
              createEncrypted(keyManagement, ctx, m)
              buffer.stash(msg)
            } else {
              val ivBytes = generateIvBytes
              cipher.init(
                Cipher.ENCRYPT_MODE,
                dataKey.secretKeySpec,
                new IvParameterSpec(ivBytes)
              )
              val encryptedBody = cipher.doFinal(bytes)
              val encrypted =
                combine(cipher.getIV, dataKey.ciphertextBlob, encryptedBody)
              replyTo ! EncryptSucceeded(encrypted)
            }
            Behaviors.same
          case Decrypt(bytes, dsi, replyTo) if dsi == dataKey.dataSubjectId =>
            val (iv, encryptedKey, encryptedBody) = divide(bytes)
            ctx.pipeToSelf[SecretKey](
              keyManagement.decryptedDataKey(encryptedKey, dsi)
            ) {
              case Success(secretKeySpec) =>
                DecryptInProgress(secretKeySpec, encryptedBody, iv, replyTo)
              case Failure(exception) => throw exception
            }
            Behaviors.same
          case DecryptInProgress(secretKey, encryptedBody, iv, replyTo) =>
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv))
            val decrypted = cipher.doFinal(encryptedBody)
            replyTo ! DecryptSucceeded(decrypted)
            Behaviors.same
          case _ =>
            Behaviors.ignore
        }
      }
      .receiveSignal {
        case (ctx, PostStop) =>
          ctx.log.info(">>> child finish")
          Behaviors.same
      }
  }

  private def generateIvBytes = {
    val ivBytes = Random.alphanumeric
      .take(16)
      .mkString
      .getBytes(StandardCharsets.UTF_8)
    ivBytes
  }

  private def childBehavior(keyManagement: KeyManagement): Behavior[Command] =
    Behaviors.withStash(256) { buffer =>
      Behaviors.setup { ctx =>
        import ctx.executionContext
        Behaviors.receiveMessage[Command] {
          case GracefulStop =>
            Behaviors.stopped
          case msg: DataKey =>
            buffer.unstashAll(created(buffer, keyManagement, msg))
          case msg: Encrypt =>
            createEncrypted(keyManagement, ctx, msg)
            buffer.stash(msg)
            Behaviors.same
          case _ =>
            Behaviors.ignore
        }
      }
    }

  private def createEncrypted(keyManagement: KeyManagement,
                              ctx: ActorContext[Command],
                              msg: Encrypt): Unit = {
    import ctx.executionContext
    val future =
      keyManagement.createEncryptedDataKey(msg.dataSubjectId)
    ctx.pipeToSelf(future) {
      case Success(EncryptedDataKeyWithSecretKey(bytes, spec)) =>
        DataKey(spec, bytes, msg.dataSubjectId)
      case Failure(exception) => throw exception
    }
  }

  def apply(
    keyManagement: KeyManagement,
    dataKeyDuration: FiniteDuration = 30.seconds
  ): Behavior[Command] =
    Behaviors.setup { ctx =>
      import ctx.executionContext
      var cancel: Cancellable = null
      Behaviors
        .receiveMessage[Command] { msg =>
          ctx.child("child") match {
            case None =>
              val childRef =
                ctx
                  .spawn(childBehavior(keyManagement), "child")
              cancel = ctx.system.scheduler
                .scheduleOnce(dataKeyDuration, { () =>
                  ctx.log.info("stop")
                  childRef ! GracefulStop
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
