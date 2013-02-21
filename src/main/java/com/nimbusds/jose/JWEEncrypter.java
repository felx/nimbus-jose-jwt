package com.nimbusds.jose;




/**
 * Interface for encrypting JSON Web Encryption (JWE) objects.
 *
 * <p>Callers can query the encrypter to determine its algorithm capabilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public interface JWEEncrypter extends JWEAlgorithmProvider {


	/**
	 * Encrypts the specified clear text of a {@link JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must specify a
	 *                  supported JWE algorithm and must not be
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
