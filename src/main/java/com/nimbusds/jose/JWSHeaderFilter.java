package com.nimbusds.jose;


import java.util.Set;


/**
 * JSON Web Signature (JWS) header filter. Specifies accepted JWS algorithms and
 * header parameters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public interface JWSHeaderFilter extends HeaderFilter {


	/**
	 * Gets the names of the accepted JWS algorithms. These correspond to 
	 * the {@code alg} JWS header parameter.
	 *
	 * @return The accepted JWS algorithms as a read-only set, empty set if 
	 *         none.
	 */
	public Set<JWSAlgorithm> getAcceptedAlgorithms();
	
	
	/**
	 * Sets the names of the accepted JWS algorithms. These correspond to 
	 * the {@code alg} JWS header parameter. 
	 *
	 * @param acceptedAlgs The accepted JWS algorithms. Must be a subset of
	 *                     the supported algorithms and not {@code null}.
	 */
	public void setAcceptedAlgorithms(Set<JWSAlgorithm> acceptedAlgs);
}
