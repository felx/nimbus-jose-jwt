package com.nimbusds.jose;


/**
 * Read-only view of a {@link JWSHeader JWS header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public interface ReadOnlyJWSHeader extends ReadOnlyCommonSEHeader {


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	@Override
	public JWSAlgorithm getAlgorithm();
}
