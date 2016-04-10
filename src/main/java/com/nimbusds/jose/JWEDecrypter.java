package com.nimbusds.jose;


import com.nimbusds.jose.util.base64.Base64URL;


/**
 * JSON Web Encryption (JWE) decrypter.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-21
 */
public interface JWEDecrypter extends JWEProvider {


	/**
	 * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
	 *
	 * @param header       The JSON Web Encryption (JWE) header. Must
	 *                     specify a supported JWE algorithm and method.
	 *                     Must not be {@code null}.
	 * @param encryptedKey The encrypted key, {@code null} if not required
	 *                     by the JWE algorithm.
	 * @param iv           The initialisation vector, {@code null} if not
	 *                     required by the JWE algorithm.
	 * @param cipherText   The cipher text to decrypt. Must not be
	 *                     {@code null}.
	 * @param authTag      The authentication tag, {@code null} if not
	 *                     required.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported, if a critical header parameter is
	 *                       not supported or marked for deferral to the
	 *                       application, or if decryption failed for some
	 *                       other reason.
	 */
	byte[] decrypt(final JWEHeader header,
		       final Base64URL encryptedKey,
		       final Base64URL iv,
		       final Base64URL cipherText,
		       final Base64URL authTag)
		throws JOSEException;
}
