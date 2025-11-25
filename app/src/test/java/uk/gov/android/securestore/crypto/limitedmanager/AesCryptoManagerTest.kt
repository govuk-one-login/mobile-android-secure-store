package uk.gov.android.securestore.crypto.limitedmanager

import org.junit.jupiter.api.Assertions.assertThrows
import java.security.GeneralSecurityException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalEncodingApi::class)
class AesCryptoManagerTest {
    private val sut = AesCryptoManager()
    private val data = "data"
    private val aesKey = "01mQIbHjYrroG3A8ELBU0H6YCkGv9CIUWvuO/LsFGDk="
    private val encryptedValue = "GTSfR2LCw5A10IqHMsExVW/qxowfT3shkP+oe1kENIV/5ZoA+mo3hW6jY+48f" +
        "xdmkzeJu5tE/U7f9BR7U7wUd8yYx5dBiEUqgDVjNveH2Sz42spVEWaRIL06V1ZKDl3lAb3EYlCy7e4qcez" +
        "sulJ5w/Wa0aSiduI0khSF8TNpAPYGugdTzxysyEtLDf/mjrY+2jz8PJ2SAzxBUQcxvn8siZ4Fe8WQTc3Hc" +
        "q9LnKgrNn8ze+iJrEv/YsHLTOs3UbMY7pLYaWYnG8pJJMZuDBiFQ6ID3WD/X9Lx2jB4sUAVn7prZfcbiH7" +
        "fSZFaS96cV22zbndH5ideKc3mKL9kwFjL8iejbE8k4oBrw/UWUY5P3eT/6zVEameD1FEuYk7yGaoxPkkmG" +
        "puwnzVGxWb3fRqIEKOPtbZ2AjNhKq478ofTwYOlSAxJgMte9zuQp1LL6wvBDv+N0yPyktGaWVLIOejwKCN" +
        "QrcQbxUGlEjrZ8h3uPgazFpz/3CtgpQTLTZs0ObvNh+0vCGlAVmwhKWmcfCbK23ByXrxtSnaJMmPOTwqfY" +
        "7PwUlSEWO4qEdLTbrJhAgAEsi0vLACeUP0R1QJqEuPHcB4z2ZXDq47/hQQmiiyPgTqRICabBkJ19PfmcJ+" +
        "NEjEAkzSBCXhedCQcI9eSmM14u2LJxolXxXsmSH38rGwvLpY4DilhlKJh9H5oMEoc7MVyUwOYI25dYnbWE" +
        "lkJAS6HuiCTmw=="
    private val expected = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImY2M2FlNDkxLWZjNzAtNGExN" +
        "S05ZThhLTkwNWQ0OWEzZmU2ZCJ9.eyJpc3MiOiJodHRwczovL21vYmlsZS5idWlsZC5hY2NvdW50Lmdvdi5" +
        "1ayIsInN1YiI6ImJZcmN1UlZ2bnlsdkVnWVNTYkJqd1h6SHJ3SiIsImV4cCI6MTczMzgzMDYxNSwiY25mIj" +
        "p7Imp3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6InJoZS1VLUFrTzF0S" +
        "XlhY1N5dl9kQUVNVFhsT19IanVsNDBGOG1ZeWljTDQiLCJ5IjoiVXZtWDlxcXlIaElTaHdfa2xNRmZqbmQ2" +
        "ZUlhZEVKZ3RhT0M3bjRnUEtrayJ9fX0.Gh0cTcrgh1sX_osWj8SCPQYcQqTNY4D40k_C2Xu3tmSZvePOFU_" +
        "ZT1jA33EvOzzC4pCASiinvXzqVWGoQXWcZA"
    private val invalidKey = Base64.encode(
        byteArrayOf(
            -10, 111, -120, 94, -43, -122, -40, 61, 23,
            12, -83, 34, 4, -96, 50, 15, 86, -35, -43, 65, -39, 116, -128, 119, 124, -3, 103, -5, -87,
            -58, 39, -124,
        ),
    )

    @Test
    fun testEncryptDataSuccess() {
        val result = sut.encrypt(data) { Base64.encode(ByteArray(32)) }

        assertTrue(checkInputIsBase64(result.data))
        assertTrue(checkInputIsBase64(result.key))
    }

    @Test
    fun testDecryptDataSuccess() {
        var result: String? = null
        result = sut.decrypt(encryptedValue, aesKey)

        assertEquals(expected, result)
    }

    @Test
    fun testDecryptDataFailureInvalidKey() {
        assertThrows(GeneralSecurityException::class.java) {
            sut.decrypt(encryptedValue, invalidKey)
        }
    }

    @Suppress("SwallowedException")
    private fun checkInputIsBase64(input: String): Boolean {
        return try {
            Base64.decode(input.toByteArray())
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }
}
