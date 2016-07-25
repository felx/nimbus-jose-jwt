package com.nimbusds.jwt.proc;


import com.nimbusds.jwt.JWTClaimsSet;


/**
 * @see JWTClaimsSetVerifier
 */
@Deprecated
public interface JWTClaimsVerifier {


	/**
	 * Performs verification of selected or all claims in the specified JWT
	 * claims set.
	 *
	 * @param claimsSet The JWT claims set. Not {@code null}.
	 *
	 * @throws BadJWTException If the JWT claims set is rejected.
	 */
	@Deprecated
	void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException;
}
