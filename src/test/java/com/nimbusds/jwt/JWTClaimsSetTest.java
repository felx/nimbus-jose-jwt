package com.nimbusds.jwt;


import java.util.Arrays;
import java.util.Date;
import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-23)
 */
public class JWTClaimsSetTest extends TestCase {


	public void testReservedNames() {
	
		Set<String> names = JWTClaimsSet.getReservedNames();
		
		assertTrue(names.contains("iss"));
		assertTrue(names.contains("sub"));
		assertTrue(names.contains("aud"));
		assertTrue(names.contains("exp"));
		assertTrue(names.contains("nbf"));
		assertTrue(names.contains("iat"));
		assertTrue(names.contains("jti"));
		assertTrue(names.contains("typ"));
		
		assertEquals(8, names.size());
	}

	public void testRun() {

		JWTClaimsSet cs = new JWTClaimsSet();

		final Date NOW = new Date();

		// iss
		assertNull("iss init check", cs.getIssuer());
		cs.setIssuer("http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", cs.getIssuer());
		
		// sub
		assertNull("sub init check", cs.getSubject());
		cs.setSubject("http://subject.com");
		assertEquals("sub set check", "http://subject.com", cs.getSubject());

		// aud
		assertNull("aud init check", cs.getAudience());		
		cs.setAudience(Arrays.asList("http://audience.com"));
		assertEquals("aud set check", "http://audience.com", cs.getAudience().get(0));
		
		// exp
		assertNull("exp init check", cs.getExpirationTime());
		cs.setExpirationTime(NOW);
		assertEquals("exp set check", NOW, cs.getExpirationTime());
		
		// nbf
		assertNull("nbf init check", cs.getNotBeforeTime());
		cs.setNotBeforeTime(NOW);
		assertEquals("nbf set check", NOW, cs.getNotBeforeTime());
		
		// iat
		assertNull("iat init check", cs.getIssueTime());
		cs.setIssueTime(NOW);
		assertEquals("iat set check", NOW, cs.getIssueTime());
		
		// jti
		assertNull("jti init check", cs.getJWTID());
		cs.setJWTID("123");
		assertEquals("jti set check", "123", cs.getJWTID());
		
		// typ
		assertNull("typ init check", cs.getType());
		cs.setType("JWT");
		assertEquals("typ set check", "JWT", cs.getType());
		
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
			cs = JWTClaimsSet.parse(json);
			
		} catch (java.text.ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("iss parse check", "http://issuer.com", cs.getIssuer());
		assertEquals("sub parse check", "http://subject.com", cs.getSubject());
		assertEquals("aud parse check", "http://audience.com", cs.getAudience().get(0));
		assertEquals("exp parse check", NOW, cs.getExpirationTime());
		assertEquals("nbf parse check", NOW, cs.getNotBeforeTime());
		assertEquals("iat parse check", NOW, cs.getIssueTime());
		assertEquals("jti parse check", "123", cs.getJWTID());
		assertEquals("typ parse check", "JWT", cs.getType());
		assertEquals("abc", (String)cs.getCustomClaim("x-custom"));
		assertEquals(1, cs.getCustomClaims().size());
	}
	
	public void testClaimsPassthrough() {
		JWTClaimsSet cs = new JWTClaimsSet();

		// reserved issuer claim
		// iss
		assertNull("iss init check", cs.getIssuer());
		cs.setClaim("iss", "http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", cs.getClaim("iss"));
		assertEquals("iss set check", "http://issuer.com", cs.getIssuer());
		
		// custom claim
		assertNull("x-custom init check", cs.getClaim("x-custom"));
		cs.setClaim("x-custom", "abc");
		assertEquals("abc", (String)cs.getClaim("x-custom"));

		// serialise
		JSONObject json = cs.toJSONObject();
		
		assertEquals(2, json.size());
		
		// parse back
		
		try {
			cs = JWTClaimsSet.parse(json);
			
		} catch (java.text.ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("iss set check", "http://issuer.com", cs.getClaim("iss"));
		assertEquals("iss set check", "http://issuer.com", cs.getIssuer());
		assertEquals("abc", (String)cs.getClaim("x-custom"));
		
	}
}
