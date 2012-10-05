package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeaderFilter;


/**
 * JSON Web Signature (JWS) header filter implementation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
class DefaultJWSHeaderFilter implements JWSHeaderFilter {


	/**
	 * The supported algorithms. Used to bound the subset of the accepted 
	 * ones.
	 */
	private final Set<JWSAlgorithm> algs;
	
	
	/**
	 * The accepted algorithms.
	 */
	private Set<JWSAlgorithm> acceptedAlgs;
	
	
	/**
	 * The accepted header parameters.
	 */
	private final Set<String> acceptedParams;
	
	 
	/**
	 * Creates a new JWS header filter. The accepted algorithms are set to
	 * equal the specified supported ones.
	 *
	 * @param algs           The supported JWS algorithms. Used to bound the
	 *                       {@link #setAcceptedAlgorithms accepted
	 *                       algorithms}. Must not be {@code null}.
	 * @param acceptedParams The accepted JWS header parameters. Must 
	 *                       contain at least the {@code alg} parameter and
	 *                       must not be {@code null}.
	 */
	public DefaultJWSHeaderFilter(final Set<JWSAlgorithm> algs,
	                              final Set<String> acceptedParams) {
	
		if (algs == null)
			throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
	
		this.algs = Collections.unmodifiableSet(algs);
		
		acceptedAlgs = this.algs;
		
		
		if (acceptedParams == null)
			throw new IllegalArgumentException("The accepted JWS header parameter set must not be null");
		
		if (! acceptedParams.contains("alg"))
			throw new IllegalArgumentException("The accepted JWE header parameter set must include at least the \"alg\" parameter");
		
		this.acceptedParams = Collections.unmodifiableSet(acceptedParams);
	}
	
	
	/**
	 * Returns the names of the supported JWS algorithms. Used to bound the 
	 * {@link #setAcceptedAlgorithms accepted algorithms}.
	 *
	 * @return The supported JWS algorithms as a read-only set, empty set if
	 *         none.
	 */
	public Set<JWSAlgorithm> supportedAlgorithms() {
	
		return algs;
	}
	
	
	@Override
	public Set<JWSAlgorithm> getAcceptedAlgorithms() {
		
		return acceptedAlgs;
	}
		
	
	@Override
	public void setAcceptedAlgorithms(Set<JWSAlgorithm> acceptedAlgs) {
	
		if (acceptedAlgs == null)
			throw new IllegalArgumentException("The accepted JWS algorithm set must not be null");
	
		if (! supportedAlgorithms().containsAll(acceptedAlgs))
			throw new IllegalArgumentException("One or more of the algorithms is not in the supported JWS algorithm set");
		
		this.acceptedAlgs = Collections.unmodifiableSet(acceptedAlgs);
	}
	
	
	@Override
	public Set<String> getAcceptedParameters() {
	
		return acceptedParams;
	}
}
