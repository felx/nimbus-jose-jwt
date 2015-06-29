package com.nimbusds.jwt.proc;


import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;


/**
 * JWT claims verifier. Intended to enable performance of various claim checks,
 * such as issuer acceptance, during {@link JWTProcessor JWT processing}
 * (after the JWT is successfully verified (for JWS) or decrypted (for JWE)).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-30
 */
public interface JWTClaimsVerifier {


	/**
	 * Performs verification of selected or all claims in the specified JWT
	 * claims set.
	 *
	 * @param claimsSet The JWT claims set. Not {@code null}.
	 *
	 * @throws BadJWTException If the JWT claims set is rejected.
	 */
	void verify(final ReadOnlyJWTClaimsSet claimsSet)
		throws BadJWTException;
}
