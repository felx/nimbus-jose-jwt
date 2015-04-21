package com.nimbusds.jose;


import java.util.Set;


/**
 * JSON Web Encryption (JWE) algorithm provider.
 *
 * <p>The JWE provider can be queried to determine its algorithm capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
public interface JWEAlgorithmProvider extends AlgorithmProvider {


	/**
	 * Returns the names of the supported JWE algorithms. These correspond
	 * to the {@code alg} JWE header parameter.
	 *
	 * @return The supported JWE algorithms, empty set if none.
	 */
	Set<JWEAlgorithm> supportedJWEAlgorithms();


	/**
	 * Returns the names of the supported encryption methods. These
	 * correspond to the {@code enc} JWE header parameter.
	 *
	 * @return The supported encryption methods, empty set if none.
	 */
	Set<EncryptionMethod> supportedEncryptionMethods();
}
