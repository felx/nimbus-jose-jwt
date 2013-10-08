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
 * @version $version$ (2013-10-07)
 */
@ThreadSafe
public class DefaultJWSHeaderFilter extends DefaultHeaderFilter implements JWSHeaderFilter {


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
	 * Validates the specified accepted parameters.
	 *
	 * @param acceptedParams The accepted JWS header parameters. Must 
	 *                       contain at least the {@code alg} parameter and
	 *                       must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the parameters didn't meet the
	 *                                  validation criteria.
	 */
	private static void validateAcceptedParameters(final Set<String> acceptedParams) {

		if (! acceptedParams.contains("alg")) {

			throw new IllegalArgumentException("The accepted JWS header parameters set must include at least the \"alg\" parameter");
		}
	}


	/**
	 * Creates a new JWS header filter. The accepted algorithms are set to
	 * equal the specified supported ones. The accepted header parameters
	 * are set to match
	 * {@link com.nimbusds.jose.JWSHeader#getRegisteredParameterNames()}.
	 *
	 * @param algs The supported JWS algorithms. Used to bound the 
	 *             {@link #setAcceptedAlgorithms accepted algorithms}. Must 
	 *             not be {@code null}.
	 */
	public DefaultJWSHeaderFilter(final Set<JWSAlgorithm> algs) {

		this(algs, JWSHeader.getRegisteredParameterNames());
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

		super(acceptedParams);

		validateAcceptedParameters(acceptedParams);

		if (algs == null) {

			throw new IllegalArgumentException("The supported JWS algorithms set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);

		// Initially the accepted set equals the supported set
		acceptedAlgs = this.algs;
	}


	/**
	 * Returns the names of the supported JWS algorithms. Used to bound the 
	 * {@link #setAcceptedAlgorithms accepted algorithms}.
	 *
	 * @return The supported JWS algorithms as a read-only set, empty set 
	 *         if none.
	 */
	public Set<JWSAlgorithm> supportedAlgorithms() {

		return algs;
	}


	@Override
	public Set<JWSAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(final Set<JWSAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {

			throw new IllegalArgumentException("The accepted JWS algorithms set must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {

			throw new IllegalArgumentException("One or more of the JWE algorithms is not in the supported set");
		}

		this.acceptedAlgs = Collections.unmodifiableSet(acceptedAlgs);
	}


	@Override
	public void setAcceptedParameters(final Set<String> acceptedParams) {

		validateAcceptedParameters(acceptedParams);

		super.setAcceptedParameters(acceptedParams);
	}
}
