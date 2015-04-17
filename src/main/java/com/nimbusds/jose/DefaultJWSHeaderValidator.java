package com.nimbusds.jose;


import java.net.URI;
import java.util.Set;

import net.jcip.annotations.Immutable;


/**
 * The default JSON Web Signature (JWS) header validator.
 */
@Immutable
public class DefaultJWSHeaderValidator implements JWSHeaderValidator {


	/**
	 * The expected JWS algorithm.
	 */
	private final JWSAlgorithm alg;


	/**
	 * The expected JWK URL.
	 */
	private final URI jku;


	/**
	 * The expected key ID.
	 */
	private final String kid;


	/**
	 * The critical header parameters to ignore.
	 */
	private final Set<String> critIgnored;


	/**
	 * Creates a new default JWS header validator.
	 *
	 * @param alg The expected JWS algorithm. Must not be {@code null}.
	 */
	public DefaultJWSHeaderValidator(final JWSAlgorithm alg) {

		this(alg, null, null);
	}


	public DefaultJWSHeaderValidator(final JWSAlgorithm alg,
					 final URI jku,
					 final String kid) {

		if (alg == null) {
			throw new IllegalArgumentException("The JWS algorithm must not be null");
		}

		this.alg = alg;

		this.jku = jku;
		this.kid = kid;
	}


	public DefaultJWSHeaderValidator withJWKURL(final URI jku) {

		return new DefaultJWSHeaderValidator(alg, jku, kid);
	}


	public DefaultJWSHeaderValidator withKeyID(final String kid) {

		return new DefaultJWSHeaderValidator(alg, jku, kid);
	}


	/**
	 * Sets the names of the critical JWS header parameters to ignore.
	 * These are indicated by the {@code crit} header parameter. The JWS
	 * verifier should not ignore critical headers by default. Use this
	 * setter to delegate processing of selected critical headers to the
	 * application.
	 *
	 * @param headers The names of the critical JWS header parameters to
	 *                ignore, empty or {@code null} if none.
	 */
	public DefaultJWSHeaderValidator withIgnoredCriticalParameters(final Set<String> critIgnored) {

		return null;
	}


	/**
	 * Gets the names of the critical JWS header parameters to ignore.
	 * These are indicated by the {@code crit} header parameter. The JWS
	 * verifier should not ignore critical headers by default.
	 *
	 * @return The names of the critical JWS header parameters to ignore,
	 *         empty or {@code null} if none.
	 */
	public Set<String> getIgnoredCriticalHeaderParameters() {

		return critIgnored;
	}


	@Override
	public void validate(JWSHeader jwsHeader)
		throws JOSEException {

	}
}
