package com.nimbusds.jose.sdk;


import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object. This class is 
 * a simple wrapper for returning return the cipher text, the encrypted key and 
 * the integrity value from {@link JWEEncrypter} implementations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-20)
 */
public final class JWEParts {


	/**
	 * The encrypted key (optional).
	 */
	final Base64URL encryptedKey;


	/**
	 * The cipher text.
	 */
	final Base64URL cipherText;


	/**
	 * The integrity value (optional).
	 */
	final Base64URL integrityValue;


	/**
	 * Creates a new cryptograhic JWE parts instance.
	 *
	 * @param encryptedKey   The encrypted key, {@code null} if not
	 *                       required by the encryption algorithm.
	 * @param cipherText     The cipher text. Must not be 
	 *                       {@code null}.
	 * @param integrityValue The integrity value according to
	 *                       {@link JWEHeader#getIntegrityAlgorithm},
	 *                       {@code null} if the JWE algorithm 
	 *                       provides built-in integrity check, else
	 *                       {@code null}.
	 */
	public JWEParts(final Base64URL encryptedKey, 
		        final Base64URL cipherText, 
		        final Base64URL integrityValue) {

		this.encryptedKey = encryptedKey;
		this.cipherText = cipherText;
		this.integrityValue = integrityValue;
	}


	/**
	 * Gets the encrypted key.
	 *
	 * @return The encrypted key, {@code null} if not required by 
	 *         the JWE algorithm.
	 */
	public Base64URL getEncryptedKey() {

		return encryptedKey;
	}


	/**
	 * Gets the cipher text.
	 *
	 * @return The cipher text.
	 */
	public Base64URL getCipherText() {

		return cipherText;
	}


	/**
	 * Gets the integrity value.
	 *
	 * @return The integrity value, {@code null} if the encryption
	 *         algorithm provides built-in integrity checking.
	 */
	 public Base64URL getIntegrityValue() {

		return integrityValue;
	}
}
