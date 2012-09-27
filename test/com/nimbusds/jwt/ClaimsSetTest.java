package com.nimbusds.jwt;


import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-27)
 */
public class ClaimsSetTest extends TestCase {


	public void testReservedNames() {
	
		Set<String> names = ClaimsSet.getReservedNames();
		
		assertTrue(names.contains("exp"));
		assertTrue(names.contains("nbf"));
		assertTrue(names.contains("iat"));
		assertTrue(names.contains("iss"));
		assertTrue(names.contains("aud"));
		assertTrue(names.contains("prn"));
		assertTrue(names.contains("jti"));
		assertTrue(names.contains("typ"));
		
		assertEquals(8, names.size());
	}

	public void testRun() {

		ClaimsSet cs = new ClaimsSet();
		
		// exp
		assertEquals("exp init check", -1, cs.getExpirationTimeClaim());
		cs.setExpirationTimeClaim(123l);
		assertEquals("exp set check", 123l, cs.getExpirationTimeClaim());
		
		// nbf
		assertEquals("nbf init check", -1, cs.getNotBeforeClaim());
		cs.setNotBeforeClaim(123l);
		assertEquals("nbf set check", 123l, cs.getNotBeforeClaim());
		
		// iat
		assertEquals("iat init check", -1, cs.getIssuedAtClaim());
		cs.setIssuedAtClaim(123l);
		assertEquals("iat set check", 123l, cs.getIssuedAtClaim());
		
		// iss
		assertNull("iss init check", cs.getIssuerClaim());
		cs.setIssuerClaim("http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", cs.getIssuerClaim());
		
		// aud
		assertNull("aud init check", cs.getAudienceClaim());
		cs.setAudienceClaim("http://audience.com");
		assertEquals("aud set check", "http://audience.com", cs.getAudienceClaim());
		
		// prn
		assertNull("prn init check", cs.getPrincipalClaim());
		cs.setPrincipalClaim("http://principal.com");
		assertEquals("prn set check", "http://principal.com", cs.getPrincipalClaim());
		
		// jti
		assertNull("jti init check", cs.getJWTIDClaim());
		cs.setJWTIDClaim("123");
		assertEquals("jti set check", "123", cs.getJWTIDClaim());
		
		// typ
		assertNull("typ init check", cs.getTypeClaim());
		cs.setTypeClaim("JWT");
		assertEquals("typ set check", "JWT", cs.getTypeClaim());
		
		// custom claims
		assertTrue(cs.getCustomClaims().isEmpty());
		
		// x-custom
		cs.setCustomClaim("x-custom", "abc");
		assertEquals("abc", (String)cs.getCustomClaim("x-custom"));
		
		assertEquals(1, cs.getCustomClaims().size());
		
		
		// serialise
		JSONObject json = cs.toJSONObject();
		
		assertEquals(9, json.size());
		
		// parse back
		
		try {
			cs = ClaimsSet.parse(json);
			
		} catch (java.text.ParseException e) {
		
			fail(e.getMessage());
		}
		
		
		assertEquals("exp parse check", 123l, cs.getExpirationTimeClaim());
		assertEquals("nbf parse check", 123l, cs.getNotBeforeClaim());
		assertEquals("iat parse check", 123l, cs.getIssuedAtClaim());
		assertEquals("iss parse check", "http://issuer.com", cs.getIssuerClaim());
		assertEquals("aud parse check", "http://audience.com", cs.getAudienceClaim());
		assertEquals("prn parse check", "http://principal.com", cs.getPrincipalClaim());
		assertEquals("jti parse check", "123", cs.getJWTIDClaim());
		assertEquals("typ parse check", "JWT", cs.getTypeClaim());
		assertEquals("abc", (String)cs.getCustomClaim("x-custom"));
		assertEquals(1, cs.getCustomClaims().size());
	}
}
