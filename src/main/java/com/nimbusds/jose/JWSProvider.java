package com.nimbusds.jose;


import java.util.Set;


/**
 * JSON Web Signature (JWS) provider
 *
 * <p>The JWS provider can be queried to determine its algorithm capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version 2015-05-26
 */
public interface JWSProvider extends JOSEProvider {


	/**
	 * Returns the names of the supported algorithms by the JWS provider
	 * instance. These correspond to the {@code alg} JWS header parameter.
	 *
	 * @return The supported JWS algorithms, empty set if none.
	 */
	Set<JWSAlgorithm> supportedJWSAlgorithms();
}
