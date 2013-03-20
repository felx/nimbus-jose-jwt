package com.nimbusds.jose;


import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;


/**
 * JSON Web Signature (JWS) header filter implementation. Intended to be
 * incorporated by {@link JWSVerifier} implementations. This class is 
 * thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-20)
 */
@ThreadSafe
public class DefaultJWSHeaderFilter implements JWSHeaderFilter {


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
	private Set<String> acceptedParams;


	/**
	 * Creates a new JWS header filter. The accepted algorithms are set to
	 * equal the specified supported ones. The accepted header parameters
	 * are set to match {@link JWSHeader#getReservedParameterNames}.
	 *
	 * @param algs           The supported JWS algorithms. Used to bound 
	 *                       the {@link #setAcceptedAlgorithms accepted
	 *                       algorithms}. Must not be {@code null}.
	 */
	public DefaultJWSHeaderFilter(final Set<JWSAlgorithm> algs) {

		this(algs, JWSHeader.getReservedParameterNames());
	}


	/**
	 * Creates a new JWS header filter. The accepted algorithms are set to
	 * equal the specified supported ones.
	 *
	 * @param algs           The supported JWS algorithms. Used to bound 
	 *                       the {@link #setAcceptedAlgorithms accepted
	 *                       algorithms}. Must not be {@code null}.
	 * @param acceptedParams The accepted JWS header parameters. Must 
	 *                       contain at least the {@code alg} parameter and
	 *                       must not be {@code null}.
	 */
	public DefaultJWSHeaderFilter(final Set<JWSAlgorithm> algs,
			              final Set<String> acceptedParams) {

		if (algs == null) {

			throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);

		acceptedAlgs = this.algs;


		if (acceptedParams == null) {
			throw new IllegalArgumentException("The accepted JWS header parameter set must not be null");
		}

		if (! acceptedParams.contains("alg")) {
			throw new IllegalArgumentException("The accepted JWE header parameter set must include at least the \"alg\" parameter");
		}

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

		if (acceptedAlgs == null) {

			throw new IllegalArgumentException("The accepted JWS algorithm set must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {

			throw new IllegalArgumentException("One or more of the algorithms is not in the supported JWS algorithm set");
		}

		this.acceptedAlgs = Collections.unmodifiableSet(acceptedAlgs);
	}


	@Override
	public Set<String> getAcceptedParameters() {

		return acceptedParams;
	}


	@Override
	public void setAcceptedParameters(final Set<String> params) {

		this.acceptedParams = params;
	}
}
