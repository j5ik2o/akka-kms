package gdpr

case class GdprSettings(keySize: Int, gcmTlen: Int) {
  def withKeySize(newKeySize: Int): GdprSettings = copy(keySize = newKeySize)
  def withGcmTlen(newGcmTlen: Int): GdprSettings = copy(gcmTlen = newGcmTlen)
}
