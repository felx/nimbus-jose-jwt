package com.nimbusds.jose;


import java.util.Set;

import com.nimbusds.jose.util.Base64URL;


/**
 * Interface for decrypting JSON Web Encryption (JWE) objects.
 *
 * <p>Callers can query the decrypter to determine its algorithm capabilities as
 * well as the JWE algorithms and header parameters that are accepted for 
 * processing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-20)
 */
public interface JWEDecrypter extends JWEAlgorithmProvider {


	/**
	 * Gets the names of the accepted JWE algorithms. These correspond to
	 * the {@code alg} JWE header parameter.
	 *
	 * @return The accepted JWE algorithms, as a read-only set, empty set
	 *         if none.
	 */
	public Set<JWEAlgorithm> getAcceptedAlgorithms();


	/**
	 * Sets the names of the accepted JWE algorithms. These correspond to
	 * the {@code alg} JWE header parameter.
	 *
	 * @param acceptedAlgs The accepted JWE algorithms. Must be a subset of
	 *                     the supported algorithms and not {@code null}.
	 */
	public void setAcceptedAlgorithms(Set<JWEAlgorithm> acceptedAlgs);


	/**
	 * Gets the names of the accepted encryption methods. These correspond
	 * to the {@code enc} JWE header parameter.
	 *
	 * @return The accepted encryption methods, as a read-only set, empty
	 *         set if none.
	 */
	public Set<EncryptionMethod> getAcceptedEncryptionMethods();


	/**
	 * Sets the names of the accepted encryption methods. These correspond
	 * to the {@code enc} JWE header parameter.
	 *
	 * @param acceptedEncs The accepted encryption methods. Must be a
	 *                     subset of the supported encryption methods and
	 *                     not {@code null}.
	 */
	public void setAcceptedEncryptionMethods(final Set<EncryptionMethod> acceptedEncs);


	/**
	 * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
	 *
	 * @param header         The JSON Web Encryption (JWE) header. Must 
	 *                       specify an accepted JWE algorithm, must contain
	 *                       only accepted header parameters, and must not 
	 *                       be {@code null}.
	 * @param encryptedKey   The encrypted key, {@code null} if not required
	 *                       by the JWE algorithm.
	 * @param iv             The initialisation vector, {@code null} if not
	 *                       required by the JWE algorithm.
	 * @param cipherText     The cipher text to decrypt. Must not be 
	 *                       {@code null}.
	 * @param authTag        The authentication tag, {@code null} if not 
	 *                       required.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm is not accepted, if a 
	 *                       header parameter is not accepted, or if
	 *                       decryption failed for some other reason.
	 */
	public byte[] decrypt(final ReadOnlyJWEHeader header, 
		              final Base64URL encryptedKey,
		              final Base64URL iv,
		              final Base64URL cipherText,
		              final Base64URL authTag)
		throws JOSEException;
}
