package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.ArrayList;
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
 * @version $version$ (2013-08-26)
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
	
	
	public void testSetClaimNull() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setIssuer("http://example.com");
		assertEquals("http://example.com", cs.getIssuer());
		cs.setClaim("iss", null);
		assertNull(cs.getIssuer());
		
		cs.setSubject("alice");
		assertEquals("alice", cs.getSubject());
		cs.setClaim("sub", null);
		assertNull(cs.getSubject());
		
		List<String> audList = new ArrayList<String>();
		audList.add("http://client.example.com");
		cs.setAudience(audList);
		assertEquals("http://client.example.com", cs.getAudience().get(0));
		cs.setClaim("aud", null);
		assertNull(cs.getAudience());
		
		Date now = new Date();
		cs.setExpirationTime(now);
		assertEquals(now, cs.getExpirationTime());
		cs.setClaim("exp", null);
		assertNull(cs.getExpirationTime());
		
		cs.setNotBeforeTime(now);
		assertEquals(now, cs.getNotBeforeTime());
		cs.setClaim("nbf", null);
		assertNull(cs.getNotBeforeTime());
		
		cs.setIssueTime(now);
		assertEquals(now, cs.getIssueTime());
		cs.setClaim("iat", null);
		assertNull(cs.getIssueTime());
		
		cs.setJWTID("123");
		assertEquals("123", cs.getJWTID());
		cs.setClaim("jti", null);
		assertNull(cs.getJWTID());
		
		cs.setType("jwt");
		assertEquals("jwt", cs.getType());
		cs.setClaim("typ", null);
		assertNull(cs.getType());
	}
	
	
	public void testGetClaimTyped()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", "abc");
		assertEquals("abc", cs.getStringClaim("string"));
		
		cs.setClaim("boolean", false);
		assertFalse(cs.getBooleanClaim("boolean"));
		
		cs.setClaim("integer", 123);
		assertEquals(123, cs.getIntegerClaim("integer").intValue());
		
		cs.setClaim("long", 456l);
		assertEquals(456l, cs.getLongClaim("long").longValue());
		
		cs.setClaim("float", 3.14f);
		assertEquals(3.14f, cs.getFloatClaim("float").floatValue());
		
		cs.setClaim("double", 3.14d);
		assertEquals(3.14d, cs.getDoubleClaim("double").doubleValue());
	}
	
	
	public void testGetClaimTypedNull()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", null);
		assertNull(cs.getStringClaim("string"));
		
		cs.setClaim("boolean", null);
		assertNull(cs.getBooleanClaim("boolean"));
		
		cs.setClaim("integer", null);
		assertNull(cs.getIntegerClaim("integer"));
		
		cs.setClaim("long", null);
		assertNull(cs.getLongClaim("long"));
		
		cs.setClaim("float", null);
		assertNull(cs.getFloatClaim("float"));
		
		cs.setClaim("double", null);
		assertNull(cs.getDoubleClaim("double"));
	}
	
	
	public void testGetClaimTypedParseException() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", 3.14);
		
		try {
			cs.getStringClaim("string");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("boolean", "123");
		
		try {
			cs.getBooleanClaim("boolean");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("integer", true);
		
		try {
			cs.getIntegerClaim("integer");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("long", "abc");
		
		try {
			cs.getLongClaim("long");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("float", true);
		
		try {
			cs.getFloatClaim("float");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("double", "abc");
		
		try {
			cs.getDoubleClaim("double");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
	}


	public void testStringAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", "http://example.com");

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com"));

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayMultipleAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com", "http://example2.com"));

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals("http://example2.com", jwtClaimsSet.getAudience().get(1));
		assertEquals(2, jwtClaimsSet.getAudience().size());
	}
}
