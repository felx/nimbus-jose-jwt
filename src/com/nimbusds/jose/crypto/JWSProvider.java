package com.nimbusds.jose.crypto;


import java.util.Set;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSAlgorithm;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and validators.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-27)
 */
public abstract class JWSProvider {


	/**
	 * The accepted algorithms, if {@code null} all are accepted.
	 */
	private Set<JWSAlgorithm> acceptedAlgs;
	
	
	/**
	 * Gets the supported JWS algorithms.
	 *
	 * @return The supported algorithms.
	 */
	public abstract Set<JWSAlgorithm> getSupportedAlgorithms();
	
	
	/**
	 * Sets the accepted JWS algorithms. These represent a subset of the 
	 * supported algorithms. Supported but not accepted algorithms will be 
	 * rejected by JWS providers when processing sign or validation 
	 * requests.
	 *
	 * @param acceptedAlgs The accepted JWS algorithms. Must be a subset of
	 *                     the supported algorithms and not {@code null}.
	 */
	public void setAcceptedAlgorithms(Set<JWSAlgorithm> acceptedAlgs) {
	
		if (! getSupportedAlgorithms().containsAll(acceptedAlgs))
			throw new IllegalArgumentException("One or more of the algorithms is not in the supported JWS algorithm set");
		
		this.acceptedAlgs = acceptedAlgs;
	}
	
	
	/**
	 * Gets the accepted JWS algorithms. These represent a subset of the 
	 * supported algorithms. Supported but not accepted algorithms will be 
	 * rejected by JWS providers when processing sign or validation 
	 * requests.
	 *
	 * @return The accepted JWS algorithms.
	 */
	public Set<JWSAlgorithm> getAcceptedAlgorithms() {
		
		if (acceptedAlgs == null)
			return getSupportedAlgorithms();
			
		else
			return acceptedAlgs;
	}
	
	
	/**
	 * Ensures the specified JWS algorithm is accepted.
	 *
	 * @param alg The JWS algorithm to check. Must not be {@code null}.
	 *
	 * @throws JOSEException If the specified JWS algorithm is not accepted.
	 */
	public void ensureAcceptedAlgorithm(final JWSAlgorithm alg)
		throws JOSEException {
		
		if (acceptedAlgs == null)
			return;
		
		if (! acceptedAlgs.contains(alg))
			throw new JOSEException("The specified \"" + alg + "\" algorithm is not accepted");
	}
}
