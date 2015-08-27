package com.nimbusds.jwt.proc;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * Tests the default JWT claims verifier.
 */
public class DefaultJWTClaimsVerifierTest extends TestCase {


	public void testValidNoClaims()
		throws BadJOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNotExpired()
		throws BadJOSEException {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testExpired() {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testNbfAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNbfDenied() {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}


	public void testAllAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}
}
