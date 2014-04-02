package com.nimbusds.jose;


import java.security.Provider;
import java.security.SecureRandom;
import java.util.Set;


/**
 * Common interface for JSON Web Encryption (JWE) {@link JWEEncrypter 
 * encrypters} and {@link JWEDecrypter decrypters}.
 *
 * <p>Callers can query the JWE provider to determine its algorithm
 * capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
public interface JWEAlgorithmProvider extends AlgorithmProvider {


	/**
	 * Returns the names of the supported JWE algorithms. These correspond 
	 * to the {@code alg} JWE header parameter.
	 *
	 * @return The supported JWE algorithms, empty set if none.
	 */
	public Set<JWEAlgorithm> supportedAlgorithms();


	/**
	 * Returns the names of the supported encryption methods. These 
	 * correspond to the {@code enc} JWE header parameter.
	 *
	 * @return The supported encryption methods, empty set if none.
	 */
	public Set<EncryptionMethod> supportedEncryptionMethods();


	/**
	 * Sets a specific JCA provider for the key encryption.
	 *
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 */
	public void setKeyEncryptionProvider(final Provider provider);


	/**
	 * Sets a specific JCA provider for the content encryption.
	 *
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 */
	public void setContentEncryptionProvider(final Provider provider);


	/**
	 * Sets a specific JCA provider for MAC computation (where required by
	 * the JWE encryption method).
	 *
	 * @param provider The JCA provider, or {@code null} to use the default
	 *                 one.
	 */
	public void setMACProvider(final Provider provider);


	/**
	 * Sets a specific secure random generator for the initialisation
	 * vector and other purposes requiring a random number.
	 *
	 * @param randomGen The secure random generator, or {@code null} to use
	 *                  the default one.
	 */
	public void setSecureRandom(final SecureRandom randomGen);
}
