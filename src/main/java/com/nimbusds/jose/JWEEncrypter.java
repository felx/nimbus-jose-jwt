package com.nimbusds.jose;


/**
 * JSON Web Encryption (JWE) encrypter.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-21
 */
public interface JWEEncrypter extends JWEProvider {


	/**
	 * Encrypts the specified clear text of a {@link JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must specify
	 *                  a supported JWE algorithm and method. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The resulting JWE crypto parts.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported or if encryption failed for some
	 *                       other internal reason.
	 */
	JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException;
}
