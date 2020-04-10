package gdpr

import com.github.j5ik2o.reactive.aws.kms.KmsAsyncClient
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.model.{
  DataKeySpec,
  DecryptRequest,
  GenerateDataKeyRequest
}

import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters._

case class EncryptedDataKeyWithSecretKey(encryptedDataKey: Array[Byte],
                                         secretKey: SecretKey)

trait KeyManagement {

  def createEncryptedDataKey(dataSubjectId: String)(
    implicit ec: ExecutionContext
  ): Future[EncryptedDataKeyWithSecretKey]

  def decryptedDataKey(encryptedDataKey: Array[Byte], dataSubjectId: String)(
    implicit ec: ExecutionContext
  ): Future[SecretKey]

}

object KeyManagement {

  def ofAwsKMS(kmsClient: KmsAsyncClient, keyId: String): KeyManagement =
    new AwsKMS(kmsClient, keyId)

}

final class AwsKMS(kmsClient: KmsAsyncClient, keyId: String)
    extends KeyManagement {

  override def createEncryptedDataKey(
    dataSubjectId: String
  )(implicit ec: ExecutionContext): Future[EncryptedDataKeyWithSecretKey] = {
    val request = GenerateDataKeyRequest
      .builder()
      .keyId(keyId)
      .keySpec(DataKeySpec.AES_256)
      .encryptionContext(Map("dataSubjectId" -> dataSubjectId).asJava)
      .build()
    kmsClient
      .generateDataKey(request)
      .map { response =>
        val secretKeySpec =
          new SecretKeySpec(response.plaintext().asByteArray(), "AES")
        val encryptedKey = response.ciphertextBlob()
        EncryptedDataKeyWithSecretKey(encryptedKey.asByteArray(), secretKeySpec)
      }
  }

  override def decryptedDataKey(
    encryptedDataKey: Array[Byte],
    dataSubjectId: String
  )(implicit ec: ExecutionContext): Future[SecretKey] = {
    val request = DecryptRequest
      .builder()
      .keyId(keyId)
      .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
      .encryptionContext(Map("dataSubjectId" -> dataSubjectId).asJava)
      .build()
    kmsClient
      .decrypt(request)
      .map { response =>
        val rawKey = response.plaintext().asByteArray()
        new SecretKeySpec(rawKey, "AES")
      }
  }
}
