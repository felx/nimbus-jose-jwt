package com.nimbusds.jwt.proc;


import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * JWT claims set verifier. Ensures the claims set of a JWT that is being
 * {@link JWTProcessor processed} complies with an application's requirements.
 *
 * <p>An application may implement JWT claims checks such as:
 *
 * <ul>
 *     <li>The JWT is within the required validity time window;
 *     <li>has a specific issuer;
 *     <li>has a specific audience;
 *     <li>has a specific subject;
 *     <li>etc.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-07-25
 * @since 4.23
 */
public interface JWTClaimsSetVerifier <C extends SecurityContext> {
	
	
	/**
	 * Verifies selected or all claims from the specified JWT claims set.
	 *
	 * @param claimsSet The JWT claims set. Not {@code null}.
	 * @param context   Optional context, {@code null} if not required.
	 *
	 * @throws BadJWTException If the JWT claims set is rejected.
	 */
	void verify(final JWTClaimsSet claimsSet, final C context)
		throws BadJWTException;
}
