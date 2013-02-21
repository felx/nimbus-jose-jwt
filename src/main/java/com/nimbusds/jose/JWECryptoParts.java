package com.nimbusds.jose;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64URL;


/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object. This class is 
 * an immutable simple wrapper for returning the cipher text, initialisation 
 * vector (IV), encrypted key and integrity value from {@link JWEEncrypter} 
 * implementations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
@Immutable
public final class JWECryptoParts {


	/**
	 * The encrypted key (optional).
	 */
	private final Base64URL encryptedKey;


	/**
	 * The initialisation vector (optional).
	 */
	private final Base64URL iv;


	/**
	 * The cipher text.
	 */
	private final Base64URL cipherText;


	/**
	 * The integrity value (optional).
	 */
	private final Base64URL integrityValue;


	/**
	 * Creates a new cryptograhic JWE parts instance.
	 *
	 * @param encryptedKey   The encrypted key, {@code null} if not
	 *                       required by the encryption algorithm.
	 * @param iv             The initialisation vector (IV), {@code null} if
	 *                       not required by the encryption algorithm.
	 * @param cipherText     The cipher text. Must not be {@code null}.
	 * @param integrityValue The integrity value, {@code null} if the JWE 
	 *                       algorithm provides built-in integrity check.
	 */
	public JWECryptoParts(final Base64URL encryptedKey, 
			final Base64URL iv,
			final Base64URL cipherText, 
			final Base64URL integrityValue) {

		this.encryptedKey = encryptedKey;

		this.iv = iv;

		if (cipherText == null) {
			throw new IllegalArgumentException("The cipher text must not be null");
		}

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
	 * Gets the initialisation vector (IV).
	 *
	 * @return The initialisation vector (IV), {@code null} if not required
	 *         by the JWE algorithm.
	 */
	public Base64URL getInitializationVector() {

		return iv;
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
