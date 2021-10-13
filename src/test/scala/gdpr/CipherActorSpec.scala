package gdpr

import akka.actor.testkit.typed.scaladsl.ScalaTestWithActorTestKit
import com.github.j5ik2o.dockerController.localstack.{LocalStackController, Service}
import com.github.j5ik2o.dockerController.{DockerController, DockerControllerSpecSupport, RandomPortUtil, WaitPredicates}
import com.sun.crypto.provider.SunJCE
import gdpr.CipherActor._
import org.scalatest.freespec.AnyFreeSpecLike
import org.scalatest.time.{Second, Seconds, Span}
import software.amazon.awssdk.auth.credentials.{AwsBasicCredentials, AwsCredentials, ProfileCredentialsProvider, StaticCredentialsProvider}
import software.amazon.awssdk.services.kms.{KmsAsyncClient => JavaKmsAsyncClient}

import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Base64
import scala.concurrent.duration.Duration
import scala.jdk.FutureConverters.CompletionStageOps
import scala.sys.env

class CipherActorSpec extends ScalaTestWithActorTestKit with AnyFreeSpecLike with DockerControllerSpecSupport {
  val accessKeyId: String         = "AKIAIOSFODNN7EXAMPLE"
  val secretAccessKey: String     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  val hostPortForKMS: Int          = RandomPortUtil.temporaryServerPort()

  val controller: LocalStackController =
    LocalStackController(dockerClient)(
      Set(Service.KMS),
      edgeHostPort = hostPortForKMS,
      hostNameExternal = Some(dockerHost)
  )

  override protected val dockerControllers: Vector[DockerController] = Vector(controller)
  override protected val waitPredicatesSettings: Map[DockerController, WaitPredicateSetting] =     Map(
    controller -> WaitPredicateSetting(Duration.Inf, WaitPredicates.forLogMessageExactly("Ready."))
  )

  override implicit val patienceConfig: PatienceConfig = PatienceConfig(Span(20, Seconds), Span(1, Second))

  "EncryptionService" - {
    "encrypt" in {
      import java.security.Security
      Security.addProvider(new SunJCE)

      val awsCredentialsProvider: Option[StaticCredentialsProvider] =
        Some(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
      val javaAsyncClientBuilder = JavaKmsAsyncClient.builder()
      val javaAsyncClient: JavaKmsAsyncClient = awsCredentialsProvider match {
        case None    => javaAsyncClientBuilder.build()
        case Some(c) => javaAsyncClientBuilder.credentialsProvider(c).endpointOverride(URI.create(s"http://${dockerHost}:${hostPortForKMS}")).build()
      }
      val key = javaAsyncClient.createKey().asScala.futureValue

      val awsKms = KeyManagement.ofAwsKMS(
        javaAsyncClient,
        key.keyMetadata().keyId()
      )
      val ref = spawn(CipherActor(awsKms))

      def encryptAndDecrypt(str: String, dataSubjectId: String) = {
        println("-------------------------")
        val probe1 = createTestProbe[EncryptReply]()
        ref ! Encrypt(
          str.getBytes(StandardCharsets.UTF_8),
          dataSubjectId,
          probe1.ref
        )
        val reply = probe1.expectMessageType[EncryptSucceeded]
        val enc = new String(Base64.getEncoder.encode(reply.bytes))
        println(enc)
        val probe2 = createTestProbe[DecryptReply]()
        ref ! Decrypt(reply.bytes, dataSubjectId, probe2.ref)
        val reply2 = probe2.expectMessageType[DecryptSucceeded]
        val s = new String(reply2.bytes, StandardCharsets.UTF_8)
        s shouldBe str
        enc
      }
      val r1 = encryptAndDecrypt("ABCDEF1", "test-1")
      r1 should not be encryptAndDecrypt("ABCDEF1", "test-1")
      encryptAndDecrypt("ABCDEF2", "test-2")
      Thread.sleep(3000)
      encryptAndDecrypt("ABCDEF1", "test-1") should not be r1

    }
  }
}
