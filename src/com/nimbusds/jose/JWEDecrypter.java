package com.nimbusds.jose;


import com.nimbusds.util.Base64URL;


/**
 * Interface for decrypting JSON Web Encryption (JWE) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-20)
 */
public interface JWEDecrypter {


	/**
	 * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
	 *
	 * @param header         The JSON Web Encryption (JWE) header. Must not be
	 *                       {@code null}.
	 * @param encryptedKey   The encrypted key, {@code null} if not required
	 *                       by the JWE algorithm.
	 * @param cipherText     The cipher text to decrypt. Must not be 
	 *                       {@code null}.
	 * @param integrityValue The integrity value, {@code null} if not 
	 *                       required by the JWE algorithm.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm is not supported or if
	 *                       decryption failed for some other reason.
	 */
	public byte[] decrypt(final ReadOnlyJWEHeader header, 
	                      final Base64URL encryptedKey,
			      final Base64URL cipherText,
			      final Base64URL integrityValue)
		throws JOSEException;
}
