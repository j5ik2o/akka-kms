package gdpr

import java.nio.charset.StandardCharsets
import java.util.Base64

import akka.actor.testkit.typed.scaladsl.ScalaTestWithActorTestKit
import com.github.j5ik2o.reactive.aws.kms.KmsAsyncClient
import com.sun.crypto.provider.SunJCE
import gdpr.CipherActor._
import org.scalatest.freespec.AnyFreeSpecLike
import org.scalatest.time.{Second, Seconds, Span}
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider
import software.amazon.awssdk.services.kms.{
  KmsAsyncClient => JavaKmsAsyncClient
}

class CipherActorSpec extends ScalaTestWithActorTestKit with AnyFreeSpecLike {
  implicit val pc = PatienceConfig(Span(20, Seconds), Span(1, Second))
  "EncryptionService" - {
    "encrypt" in {
      import java.security.Security
      Security.addProvider(new SunJCE)

      val awsCredentialsProvider: Option[ProfileCredentialsProvider] =
        Some(ProfileCredentialsProvider.create("gdpr"))
      val javaAsyncClientBuilder = JavaKmsAsyncClient.builder()
      val javaAsyncClient = awsCredentialsProvider match {
        case None    => javaAsyncClientBuilder.build()
        case Some(c) => javaAsyncClientBuilder.credentialsProvider(c).build()
      }
      val kmsAsyncClient: KmsAsyncClient = KmsAsyncClient(javaAsyncClient)
      val awsKms = KeyManagement.ofAwsKMS(
        kmsAsyncClient,
        "arn:aws:kms:ap-northeast-1:738575627980:key/067523e6-adbb-4e5f-a6ed-ed9388de410c"
      )
      val ref = spawn(CipherActor.behavior(awsKms))

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
