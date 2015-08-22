package com.nimbusds.jwt;


/**
 * Generic JWT claims set type transformer. Implementations should be
 * tread-safe.
 */
public interface JWTClaimsSetTransformer<T> {


	/**
	 * Transforms the specified JWT claims set into the desired type.
	 *
	 * @param claimsSet The JWT claims set. Not {@code null}.
	 *
	 * @return The desired type.
	 */
	T transform(final JWTClaimsSet claimsSet);
}
