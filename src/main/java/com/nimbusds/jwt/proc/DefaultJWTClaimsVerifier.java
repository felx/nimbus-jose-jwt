package com.nimbusds.jwt.proc;


import java.util.Date;

import com.nimbusds.jose.util.DateUtils;
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
 * @version 2015-12-13
 */
@ThreadSafe
public class DefaultJWTClaimsVerifier implements JWTClaimsVerifier, ClockSkewAware {


	/**
	 * The default maximum acceptable clock skew, in seconds (60).
	 */
	public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;


	// Cache exceptions


	/**
	 * Expired JWT.
	 */
	private static final BadJWTException EXPIRED_JWT_EXCEPTION = new BadJWTException("Expired JWT");


	/**
	 * JWT before use time.
	 */
	private static final BadJWTException JWT_BEFORE_USE_EXCEPTION = new BadJWTException("JWT before use time");


	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew = DEFAULT_MAX_CLOCK_SKEW_SECONDS;


	@Override
	public int getMaxClockSkew() {
		return maxClockSkew;
	}


	@Override
	public void setMaxClockSkew(int maxClockSkewSeconds) {
		maxClockSkew = maxClockSkewSeconds;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		final Date now = new Date();

		final Date exp = claimsSet.getExpirationTime();

		if (exp != null) {

			if (! DateUtils.isAfter(exp, now, maxClockSkew)) {
				throw EXPIRED_JWT_EXCEPTION;
			}
		}

		final Date nbf = claimsSet.getNotBeforeTime();

		if (nbf != null) {

			if (! DateUtils.isBefore(nbf, now, maxClockSkew)) {
				throw JWT_BEFORE_USE_EXCEPTION;
			}
		}
	}
}
