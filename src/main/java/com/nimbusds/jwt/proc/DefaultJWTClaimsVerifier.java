package com.nimbusds.jwt.proc;


import java.util.Date;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jwt.JWTClaimsSet;


/**
 * Default JWT claims verifier. This class is thread-safe.
 *
 * <p>Performs the following checks:
 *
 * <ol>
 *     <li>If an expiration time (exp) claim is present, makes sure it is
 *         ahead of the current time, else the JWT claims set is rejected.
 *     <li>If a not-before-time (nbf) claim is present, makes sure it is
 *         before the current time, else the JWT claims set is rejected.
 * </ol>
 *
 * <p>This class may be extended to perform additional checks.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-27
 */
@ThreadSafe
public class DefaultJWTClaimsVerifier implements JWTClaimsVerifier {


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		final Date now = new Date();

		final Date exp = claimsSet.getExpirationTime();

		if (exp != null) {

			if (now.after(exp)) {
				throw new BadJWTException("Expired JWT");
			}
		}

		final Date nbf = claimsSet.getNotBeforeTime();

		if (nbf != null) {

			if (now.before(nbf)) {
				throw new BadJWTException("JWT before use time");
			}
		}
	}
}
