package com.nimbusds.jose;


import java.util.Set;


/**
 * Common interface for JSON Web Encryption (JWE) {@link JWEEncrypter 
 * encrypters} and {@link JWEDecrypter decrypters}.
 *
 * <p>Callers can query the JWS provider to determine its algorithm 
 * capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2012-10-16)
 */
public interface JWEAlgorithmProvider {


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
}
