package com.nimbusds.jose.sdk;


import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Interface for encrypting JSON Web Encryption (JWE) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-27)
 */
public interface JWEEncrypter {


	/**
	 * Encrypts the specified clear text of a {@link JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The resulting JWE crypto parts.
	 *
	 * @throws JOSEException If the JWE algorithm is not supported or if
	 *                       encryption failed for some other reason.
	 */
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader header, 
	                              final byte[] clearText)
		throws JOSEException;
}
