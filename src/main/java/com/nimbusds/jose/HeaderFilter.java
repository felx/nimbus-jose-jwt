package com.nimbusds.jose;


import java.util.Set;


/**
 * Javascript Object Signing and Encryption (JOSE) header filter. Specifies the
 * names of the accepted header parameters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
public interface HeaderFilter {


	/**
	 * Gets the names of the accepted header parameters.
	 *
	 * @return The accepted header parameters, as a read-only set. Should 
	 *         contain at least the {@code alg} parameter for JWS headers 
	 *         or the {@code alg} and / or {@code enc} parameters for JWE 
	 *         headers.
	 */
	public Set<String> getAcceptedParameters();


	/**
	 * Sets the names of the accepted header parameters.
	 *
	 * @param acceptedParams The accepted header parameters. Should contain 
	 *                       at least the {@code alg} parameter for JWS 
	 *                       headers or the {@code alg} and / or 
	 *                       {@code enc} parameters for JWE headers. Must 
	 *                       not be {@code null}.
	 */
	public void setAcceptedParameters(final Set<String> acceptedParams);
}
