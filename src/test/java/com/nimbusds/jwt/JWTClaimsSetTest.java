package com.nimbusds.jwt;


import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-07-26)
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

		// JWT time claim precision is seconds
		final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);

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


		Map<String,Object> all = cs.getAllClaims();

		assertEquals("iss parse check map", "http://issuer.com", (String)all.get("iss"));
		assertEquals("sub parse check map", "http://subject.com", (String)all.get("sub"));
		assertEquals("aud parse check map", "http://audience.com", (String)((List)all.get("aud")).get(0));
		assertEquals("exp parse check map", NOW, all.get("exp"));
		assertEquals("nbf parse check map", NOW, all.get("nbf"));
		assertEquals("iat parse check map", NOW, all.get("iat"));
		assertEquals("jti parse check map", "123", (String)all.get("jti"));
		assertEquals("typ parse check map", "JWT", (String)all.get("typ"));
		assertEquals("abc", (String)all.get("x-custom"));
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


	public void testDateConversion() {

		JWTClaimsSet cs = new JWTClaimsSet();

		final Date ONE_MIN_AFTER_EPOCH = new Date(1000*60);

		cs.setIssueTime(ONE_MIN_AFTER_EPOCH);
		cs.setNotBeforeTime(ONE_MIN_AFTER_EPOCH);
		cs.setExpirationTime(ONE_MIN_AFTER_EPOCH);

		JSONObject json = cs.toJSONObject();

		assertEquals(new Long(60l), (Long)json.get("iat"));
		assertEquals(new Long(60l), (Long)json.get("nbf"));
		assertEquals(new Long(60l), (Long)json.get("exp"));
	}
	
	
	public void testSetCustomClaimsNull() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		assertEquals(1, cs.getCustomClaims().size());
		
		cs.setCustomClaims(null);
		
		assertTrue(cs.getCustomClaims().isEmpty());
	}
	
	
	public void testSetCustomClaimsEmpty() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		assertEquals(1, cs.getCustomClaims().size());
		
		cs.setCustomClaims(new HashMap<String,Object>());
		
		assertTrue(cs.getCustomClaims().isEmpty());
	}
	
	
	public void testSetCustomClaims() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		assertEquals(1, cs.getCustomClaims().size());
		
		Map<String,Object> newCustomClaims = new HashMap<String,Object>();
		newCustomClaims.put("locale", "es-ES");
		newCustomClaims.put("ip", "127.0.0.1");
		
		cs.setCustomClaims(newCustomClaims);
		
		assertEquals(2, cs.getCustomClaims().size());
		
		assertEquals("es-ES", (String)cs.getCustomClaims().get("locale"));
		assertEquals("127.0.0.1", (String)cs.getCustomClaims().get("ip"));
	}
	
	
	public void testGetClaimValueNotSpecified() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		assertNull(cs.getClaim("xyz"));
	}
}
