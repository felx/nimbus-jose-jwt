package com.nimbusds.jose;


import java.util.Set;


/**
 * JSON Web Signature (JWS) algorithm provider
 *
 * <p>The JWS provider can be queried to determine its algorithm capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
public interface JWSAlgorithmProvider extends AlgorithmProvider {


	/**
	 * Returns the names of the supported JWS algorithms. These correspond
	 * to the {@code alg} JWS header parameter.
	 *
	 * @return The supported JWS algorithms, empty set if none.
	 */
	Set<JWSAlgorithm> supportedJWSAlgorithms();
}
