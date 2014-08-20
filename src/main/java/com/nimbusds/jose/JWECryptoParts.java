package com.nimbusds.jose;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64URL;


/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object. This class is 
 * an immutable wrapper for returning the cipher text, initialisation vector
 * (IV), encrypted key and authentication authTag from {@link JWEEncrypter}
 * implementations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-11)
 */
@Immutable
public final class JWECryptoParts {


	/**
	 * The modified JWE header (optional).
	 */
	private final JWEHeader header;


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
	 * The authentication tag (optional).
	 */
	private final Base64URL authenticationTag;


	/**
	 * Creates a new cryptographic JWE parts instance.
	 *
	 * @param encryptedKey      The encrypted key, {@code null} if not
	 *                          required by the encryption algorithm.
	 * @param iv                The initialisation vector (IV), 
	 *                          {@code null} if not required by the 
	 *                          encryption algorithm.
	 * @param cipherText        The cipher text. Must not be {@code null}.
	 * @param authenticationTag The authentication tag, {@code null} if the
	 *                          JWE algorithm provides built-in integrity 
	 *                          check.
	 */
	public JWECryptoParts(final Base64URL encryptedKey, 
		              final Base64URL iv,
		              final Base64URL cipherText, 
		              final Base64URL authenticationTag) {

		this(null, encryptedKey, iv, cipherText, authenticationTag);
	}


	/**
	 * Creates a new cryptographic JWE parts instance.
	 *
	 * @param header            The modified JWE header, {@code null} if
	 *                          not.
	 * @param encryptedKey      The encrypted key, {@code null} if not
	 *                          required by the encryption algorithm.
	 * @param iv                The initialisation vector (IV),
	 *                          {@code null} if not required by the
	 *                          encryption algorithm.
	 * @param cipherText        The cipher text. Must not be {@code null}.
	 * @param authenticationTag The authentication tag, {@code null} if the
	 *                          JWE algorithm provides built-in integrity
	 *                          check.
	 */
	public JWECryptoParts(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authenticationTag) {

		this.header = header;

		this.encryptedKey = encryptedKey;

		this.iv = iv;

		if (cipherText == null) {

			throw new IllegalArgumentException("The cipher text must not be null");
		}

		this.cipherText = cipherText;

		this.authenticationTag = authenticationTag;
	}


	/**
	 * Gets the modified JWE header.
	 *
	 * @return The modified JWE header, {@code null} of not.
	 */
	public JWEHeader getHeader() {

		return header;
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
	 * Gets the authentication tag.
	 *
	 * @return The authentication tag, {@code null} if the encryption
	 *         algorithm provides built-in integrity checking.
	 */
	public Base64URL getAuthenticationTag() {

		return authenticationTag;
	}


	/**
	 * Use {@link #getAuthenticationTag} instead.
	 */
	@Deprecated
	public Base64URL getIntegrityValue() {

		return getAuthenticationTag();
	}
}
