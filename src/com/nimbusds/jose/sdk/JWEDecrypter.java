package com.nimbusds.jose.sdk;


import java.util.Set;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Interface for decrypting JSON Web Encryption (JWE) objects.
 *
 * <p>Callers can query the decrypter to determine its algorithm capabilities as
 * well as the JWE algorithms and header parameters that are accepted for 
 * processing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public interface JWEDecrypter extends JWEAlgorithmProvider {

	
	/**
	 * Gets the JWE header filter associated with the decrypter. Specifies 
	 * the names of those {@link #supportedAlgorithms supported JWE 
	 * algorithms} and header parameters that the decrypter is configured to
	 * accept.
	 *
	 * <p>Attempting to {@link #decrypt decrypt} a JWE object with an
	 * algorithm or header parameter that is not accepted must result in a 
	 * {@link JOSEException}.
	 *
	 * @return The JWE header filter.
	 */
	public JWEHeaderFilter getJWEHeaderFilter();
	
	
	/**
	 * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
	 *
	 * @param header         The JSON Web Encryption (JWE) header. Must 
	 *                       specify an accepted JWE algorithm, must contain
	 *                       only accepted header parameters, and must not 
	 *                       be {@code null}.
	 * @param encryptedKey   The encrypted key, {@code null} if not required
	 *                       by the JWE algorithm.
	 * @param cipherText     The cipher text to decrypt. Must not be 
	 *                       {@code null}.
	 * @param integrityValue The integrity value, {@code null} if not 
	 *                       required by the JWE algorithm.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm is not accepted, if a 
	 *                       header parameter is not accepted, or if
	 *                       decryption failed for some other reason.
	 */
	public byte[] decrypt(final ReadOnlyJWEHeader header, 
	                      final Base64URL encryptedKey,
			      final Base64URL cipherText,
			      final Base64URL integrityValue)
		throws JOSEException;
}
