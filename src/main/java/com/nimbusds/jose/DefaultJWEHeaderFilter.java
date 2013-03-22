package com.nimbusds.jose;


import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;


/**
 * JSON Web Encryption (JWE) header filter implementation. Intended to be
 * incorporated by {@link JWEDecrypter} implementations. This class is 
 * thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
@ThreadSafe
public class DefaultJWEHeaderFilter extends DefaultHeaderFilter implements JWEHeaderFilter {


	/**
	 * The supported algorithms. Used to bound the subset of the accepted 
	 * ones.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The accepted algorithms.
	 */
	private Set<JWEAlgorithm> acceptedAlgs;


	/**
	 * The supported encryption methods. Used to bound the subset of the
	 * accepted ones.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * The accepted encryption methods.
	 */
	private Set<EncryptionMethod> acceptedEncs;


	/**
	 * Validates the specified accepted parameters.
	 *
	 * @param acceptedParams The accepted JWE header parameters. Must 
	 *                       contain at least the {@code alg} and
	 *                       {@code enc} parameters. Must not be
	 *                       {@code null}.
	 *
	 * @throws IllegalArgumentException If the parameters didn't meet the
	 *                                  validation criteria.
	 */
	private static void validateAcceptedParameters(final Set<String> acceptedParams) {

		if (! acceptedParams.contains("alg") || ! acceptedParams.contains("enc")) {

			throw new IllegalArgumentException("The accepted JWE header parameters set must include at least the \"alg\" and \"enc\" parameters");
		}
	}


	/**
	 * Creates a new JWE header filter. The accepted algorithms and
	 * encryption methods are set to equal the specified supported ones. 
	 * The accepted header parameters are set to match 
	 * {@link JWEHeader#getReservedParameterNames}.
	 *
	 * @param algs The supported JWE algorithms. Used to bound the 
	 *             {@link #setAcceptedAlgorithms accepted algorithms}. Must
	 *             not be {@code null}.
	 * @param encs The supported encryption methods. Used to bound the
	 *             {@link #setAcceptedEncryptionMethods accepted encryption
	 *             methods}. Must not be {@code null}.
	 */
	public DefaultJWEHeaderFilter(final Set<JWEAlgorithm> algs,
		                      final Set<EncryptionMethod> encs) {

		this(algs, encs, JWEHeader.getReservedParameterNames());
	}


	/**
	 * Creates a new JWE header filter. The accepted algorithms and 
	 * encryption methods are set to equal the specified supported ones.
	 *
	 * @param algs           The supported JWE algorithms. Used to bound 
	 *                       the {@link #setAcceptedAlgorithms accepted
	 *                       algorithms}. Must not be {@code null}.
	 * @param encs           The supported encryption methods. Used to
	 *                       bound the {@link #setAcceptedEncryptionMethods
	 *                       accepted encryption methods}. Must not be
	 *                       {@code null}.
	 * @param acceptedParams The accepted JWE header parameters. Must 
	 *                       contain at least the {@code alg} and
	 *                       {@code enc} parameters. Must not be
	 *                       {@code null}.
	 */
	public DefaultJWEHeaderFilter(final Set<JWEAlgorithm> algs,
		                      final Set<EncryptionMethod> encs,
			              final Set<String> acceptedParams) {

		super(acceptedParams);

		validateAcceptedParameters(acceptedParams);

		if (algs == null) {

			throw new IllegalArgumentException("The supported JWE algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);

		// Initially the accepted set equals the supported set
		acceptedAlgs = this.algs;


		if (encs == null) {

			throw new IllegalArgumentException("The supported encryption methods set must not be null");
		}

		this.encs = Collections.unmodifiableSet(encs);

		// Initially the accepted set equals the supported set
		acceptedEncs = this.encs;
	}


	/**
	 * Returns the names of the supported JWE algorithms. Used to bound the 
	 * {@link #setAcceptedAlgorithms accepted algorithms}.
	 *
	 * @return The supported JWE algorithms as a read-only set, empty set 
	 *         if none.
	 */
	public Set<JWEAlgorithm> supportedAlgorithms() {

		return algs;
	}


	@Override
	public Set<JWEAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(Set<JWEAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {

			throw new IllegalArgumentException("The accepted JWE algorithm set must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {

			throw new IllegalArgumentException("One or more of the JWE algorithms is not in the supported set");
		}

		this.acceptedAlgs = Collections.unmodifiableSet(acceptedAlgs);
	}


	/**
	 * Returns the names of the supported encryption methods. Used to bound
	 * the {@link #setAcceptedEncryptionMethods accepted encryption 
	 * methods}.
	 *
	 * @return The supported encryption methods as a read-only set, empty 
	 *         set if none.
	 */
	public Set<EncryptionMethod> supportedEncryptionMethods() {

		return encs;
	}


	@Override
	public Set<EncryptionMethod> getAcceptedEncryptionMethods() {

		return acceptedEncs;
	}

	
	@Override
	public void setAcceptedEncryptionMethods(final Set<EncryptionMethod> acceptedEncs) {

		if (acceptedEncs == null) {

			throw new IllegalArgumentException("The accepted encryption methods set must not be null");
		}

		if (! encs.containsAll(acceptedEncs)) {

			throw new IllegalArgumentException("One or more of the encryption methods is not in the supported set");
		}

		this.acceptedEncs = Collections.unmodifiableSet(acceptedEncs);

	}


	@Override
	public void setAcceptedParameters(final Set<String> acceptedParams) {

		validateAcceptedParameters(acceptedParams);

		super.setAcceptedParameters(acceptedParams);
	}
}
