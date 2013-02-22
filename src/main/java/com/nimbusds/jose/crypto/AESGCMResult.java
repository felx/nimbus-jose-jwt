package com.nimbusds.jose.crypto;


import net.jcip.annotations.Immutable;


/**
 * Encapsulates the result of an AES GCM encryption. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-22)
 */
@Immutable
class AESGCMResult {


	/**
	 * The cipher text.
	 */
	private final byte[] cipherText;


	/**
	 * The authentication tag.
	 */
	private final byte[] authTag;


	/**
	 * Creates a new AES GCM encryption result.
	 *
	 * @param cipherText The cipher text. Must not be {@code null}.
	 * @param authTag    The authentication tag. Must not be {@code null}.
	 */
	public AESGCMResult(final byte[] cipherText, final byte[] authTag) {

		this.cipherText = cipherText;

		this.authTag = authTag;
	}


	/**
	 * Gets the cipher text.
	 *
	 * @return The cipher text.
	 */
	public byte[] getCipherText() {

		return cipherText;
	}


	/**
	 * Gets the authentication tag.
	 *
	 * @return The authentication tag.
	 */
	public byte[] getAuthenticationTag() {

		return authTag;
	}
}