package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2015-08-19
 */
public class JWTClaimsSetTest extends TestCase {


	public void testReservedNames() {

		Set<String> names = JWTClaimsSet.getRegisteredNames();

		assertTrue(names.contains("iss"));
		assertTrue(names.contains("sub"));
		assertTrue(names.contains("aud"));
		assertTrue(names.contains("exp"));
		assertTrue(names.contains("nbf"));
		assertTrue(names.contains("iat"));
		assertTrue(names.contains("jti"));

		assertEquals(7, names.size());
	}


	public void testRun() {

		JWTClaimsSet cs = new JWTClaimsSet();

		// JWT time claim precision is seconds
		final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);

		// iss
		assertNull("iss init check", cs.getIssuer());
		cs = cs.withIssuer("http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", cs.getIssuer());

		// sub
		assertNull("sub init check", cs.getSubject());
		cs = cs.withSubject("http://subject.com");
		assertEquals("sub set check", "http://subject.com", cs.getSubject());

		// aud
		assertNull("aud init check", cs.getAudience());		
		cs = cs.withAudience(Arrays.asList("http://audience.com"));
		assertEquals("aud set check", "http://audience.com", cs.getAudience().get(0));

		// exp
		assertNull("exp init check", cs.getExpirationTime());
		cs = cs.withExpirationTime(NOW);
		assertEquals("exp set check", NOW, cs.getExpirationTime());

		// nbf
		assertNull("nbf init check", cs.getNotBeforeTime());
		cs = cs.withNotBeforeTime(NOW);
		assertEquals("nbf set check", NOW, cs.getNotBeforeTime());

		// iat
		assertNull("iat init check", cs.getIssueTime());
		cs = cs.withIssueTime(NOW);
		assertEquals("iat set check", NOW, cs.getIssueTime());

		// jti
		assertNull("jti init check", cs.getJWTID());
		cs = cs.withJWTID("123");
		assertEquals("jti set check", "123", cs.getJWTID());

		// no custom claims
		assertEquals(7, cs.getClaims().size());

		// x-custom
		cs = cs.withClaim("x-custom", "abc");
		assertEquals("abc", (String)cs.getClaim("x-custom"));


		// serialise
		JSONObject json = cs.toJSONObject();

		assertEquals(8, json.size());

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
		assertEquals("abc", (String)cs.getClaim("x-custom"));
		assertEquals(8, cs.getClaims().size());


		Map<String,Object> all = cs.getClaims();

		assertEquals("iss parse check map", "http://issuer.com", (String)all.get("iss"));
		assertEquals("sub parse check map", "http://subject.com", (String)all.get("sub"));
		assertEquals("aud parse check map", "http://audience.com", (String)((List)all.get("aud")).get(0));
		assertEquals("exp parse check map", NOW, all.get("exp"));
		assertEquals("nbf parse check map", NOW, all.get("nbf"));
		assertEquals("iat parse check map", NOW, all.get("iat"));
		assertEquals("jti parse check map", "123", (String)all.get("jti"));
		assertEquals("abc", (String)all.get("x-custom"));
	}


	public void testDateConversion() {

		JWTClaimsSet cs = new JWTClaimsSet();

		final Date ONE_MIN_AFTER_EPOCH = new Date(1000*60);

		cs = cs.withIssueTime(ONE_MIN_AFTER_EPOCH);
		cs = cs.withNotBeforeTime(ONE_MIN_AFTER_EPOCH);
		cs = cs.withExpirationTime(ONE_MIN_AFTER_EPOCH);

		JSONObject json = cs.toJSONObject();

		assertEquals(new Long(60l), json.get("iat"));
		assertEquals(new Long(60l), json.get("nbf"));
		assertEquals(new Long(60l), json.get("exp"));
	}
	
	
	public void testSetAndResetCustomClaim() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withClaim("locale", "bg-BG");
		
		assertEquals(1, cs.getClaims().size());
		
		cs = cs.withClaim("locale", null);

		assertNull(cs.getClaim("locale"));
		
		assertEquals(1, cs.getClaims().size());
	}
	
	
	public void testSetCustomClaims() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withClaim("locale", "bg-BG");
		assertEquals(1, cs.getClaims().size());

		cs = cs.withClaim("locale", "es-ES");
		assertEquals(1, cs.getClaims().size());

		cs = cs.withClaim("ip", "127.0.0.1");
		assertEquals(2, cs.getClaims().size());
		
		assertEquals("es-ES", (String)cs.getClaims().get("locale"));
		assertEquals("127.0.0.1", (String)cs.getClaims().get("ip"));
	}
	
	
	public void testGetClaimValueNotSpecified() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		assertNull(cs.getClaim("xyz"));
	}
	
	
	public void testSetClaimNull() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withIssuer("http://example.com");
		assertEquals("http://example.com", cs.getIssuer());
		cs = cs.withClaim("iss", null);
		assertNull(cs.getIssuer());
		
		cs = cs.withSubject("alice");
		assertEquals("alice", cs.getSubject());
		cs = cs.withClaim("sub", null);
		assertNull(cs.getSubject());
		
		List<String> audList = new ArrayList<>();
		audList.add("http://client.example.com");
		cs = cs.withAudience(audList);
		assertEquals("http://client.example.com", cs.getAudience().get(0));
		cs = cs.withClaim("aud", null);
		assertNull(cs.getAudience());
		
		Date now = new Date();
		cs = cs.withExpirationTime(now);
		assertEquals(now, cs.getExpirationTime());
		cs = cs.withClaim("exp", null);
		assertNull(cs.getExpirationTime());
		
		cs = cs.withNotBeforeTime(now);
		assertEquals(now, cs.getNotBeforeTime());
		cs = cs.withClaim("nbf", null);
		assertNull(cs.getNotBeforeTime());
		
		cs = cs.withIssueTime(now);
		assertEquals(now, cs.getIssueTime());
		cs = cs.withClaim("iat", null);
		assertNull(cs.getIssueTime());
		
		cs = cs.withJWTID("123");
		assertEquals("123", cs.getJWTID());
		cs = cs.withClaim("jti", null);
		assertNull(cs.getJWTID());
	}
	
	
	public void testGetClaimTyped()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withClaim("string", "abc");
		assertEquals("abc", cs.getStringClaim("string"));
		
		cs = cs.withClaim("boolean", false);
		assertFalse(cs.getBooleanClaim("boolean"));
		
		cs = cs.withClaim("integer", 123);
		assertEquals(123, cs.getIntegerClaim("integer").intValue());
		
		cs = cs.withClaim("long", 456l);
		assertEquals(456l, cs.getLongClaim("long").longValue());

		Date date = new Date(999000l);
		cs = cs.withClaim("date", date);
		assertEquals(date, cs.getDateClaim("date"));

		// Convert Unix timestamp to Java date
		cs = cs.withClaim("date-long", 999l);
		assertEquals(new Date(999000l), cs.getDateClaim("date-long"));
		
		cs = cs.withClaim("float", 3.14f);
		assertEquals(3.14f, cs.getFloatClaim("float").floatValue());
		
		cs = cs.withClaim("double", 3.14d);
		assertEquals(3.14d, cs.getDoubleClaim("double").doubleValue());
	}
	
	
	public void testGetClaimTypedNull()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withClaim("string", null);
		assertNull(cs.getStringClaim("string"));
		
		cs = cs.withClaim("boolean", null);
		assertNull(cs.getBooleanClaim("boolean"));
		
		cs = cs.withClaim("integer", null);
		assertNull(cs.getIntegerClaim("integer"));
		
		cs = cs.withClaim("long", null);
		assertNull(cs.getLongClaim("long"));
		
		cs = cs.withClaim("date", null);
		assertNull(cs.getDateClaim("date"));
		
		cs = cs.withClaim("float", null);
		assertNull(cs.getFloatClaim("float"));
		
		cs = cs.withClaim("double", null);
		assertNull(cs.getDoubleClaim("double"));
	}
	
	
	public void testGetClaimTypedParseException() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs = cs.withClaim("string", 3.14);
		
		try {
			cs.getStringClaim("string");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("boolean", "123");
		
		try {
			cs.getBooleanClaim("boolean");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("integer", true);
		
		try {
			cs.getIntegerClaim("integer");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("long", "abc");
		
		try {
			cs.getLongClaim("long");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("date", "abc");
		
		try {
			cs.getDateClaim("date");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("float", true);
		
		try {
			cs.getFloatClaim("float");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs = cs.withClaim("double", "abc");
		
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

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com"));

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayMultipleAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com", "http://example2.com"));

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals("http://example2.com", jwtClaimsSet.getAudience().get(1));
		assertEquals(2, jwtClaimsSet.getAudience().size());
	}


	public void testParseExampleIDToken()
		throws Exception {

		String json = "{\"exp\":1384798159,\"sub\":\"alice\",\"aud\":[\"000001\"],\"iss\":\"https:\\/\\/localhost:8080\\/c2id\",\"login_geo\":{\"long\":\"37.3956\",\"lat\":\"-122.076\"},\"login_ip\":\"185.7.248.1\",\"iat\":1384797259,\"acr\":\"urn:mace:incommon:iap:silver\",\"c_hash\":\"vwVj99I7FizReIt5q3UwhQ\",\"amr\":[\"mfa\"]}";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		assertEquals(1384798159l, claimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(1384797259l, claimsSet.getIssueTime().getTime() / 1000);

		assertEquals("alice", claimsSet.getSubject());

		assertEquals("000001", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());

		assertEquals("https://localhost:8080/c2id", claimsSet.getIssuer());

		assertEquals("urn:mace:incommon:iap:silver", claimsSet.getStringClaim("acr"));

		assertEquals("vwVj99I7FizReIt5q3UwhQ", claimsSet.getStringClaim("c_hash"));

		assertEquals("mfa", ((List<String>)claimsSet.getClaim("amr")).get(0));
		assertEquals(1, ((List<String>)claimsSet.getClaim("amr")).size());

		assertEquals("185.7.248.1", claimsSet.getStringClaim("login_ip"));

		JSONObject geoLoc = (JSONObject)claimsSet.getClaim("login_geo");

		// {"long":"37.3956","lat":"-122.076"}
		assertEquals("37.3956", (String)geoLoc.get("long"));
		assertEquals("-122.076", (String)geoLoc.get("lat"));
	}


	public void testSingleValuedAudienceSetter() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		assertNull(claimsSet.getAudience());

		claimsSet = claimsSet.withAudience("123");
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());

		claimsSet = claimsSet.withAudience((String) null);
		assertNull(claimsSet.getAudience());
	}


	public void testSerializeSingleValuedAudience()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet = claimsSet.withAudience("123");

		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals("123", (String)jsonObject.get("aud"));
		assertEquals(1, jsonObject.size());

		claimsSet = JWTClaimsSet.parse(jsonObject.toJSONString());
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());
	}


	public void testGetAllClaimsEmpty() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		assertTrue(claimsSet.getClaims().isEmpty());
	}


	public void testParseOIDCAuthz()
		throws Exception {

		String json = "{\"sub\":\"alice\",\"irt\":true,\"rft\":\"YWxpY2U.aHR0cDovL2NsaWVudDEuZXhhbXBsZS5jb20.rsKHqBpyEh-MMtllO7chHg\",\"aud\":[\"http:\\/\\/userinfo.example.com\"],\"iss\":\"http:\\/\\/oidc.example.com\",\"ate\":\"IDENTIFIER\",\"lng\":true,\"iat\":1420544052,\"cid\":\"http:\\/\\/client1.example.com\"}";
		JWTClaimsSet.parse(json);
	}


	public void testAudienceParsing()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray aud = new JSONArray();
		aud.add("client-1");
		aud.add("client-2");
		jsonObject.put("aud", aud);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);
		assertEquals("client-1", claimsSet.getAudience().get(0));
		assertEquals("client-2", claimsSet.getAudience().get(1));
		assertEquals(2, claimsSet.getAudience().size());
	}


	public void testGetStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		String[] strings = claimsSet.getStringArrayClaim("array");
		assertEquals("client-1", strings[0]);
		assertEquals("client-2", strings[1]);
		assertEquals(2, strings.length);
	}


	public void testGetInvalidStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringArrayClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		assertNull(claimsSet.getStringArrayClaim("array"));
	}


	public void testGetStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		List<String> strings = claimsSet.getStringListClaim("array");
		assertEquals("client-1", strings.get(0));
		assertEquals("client-2", strings.get(1));
		assertEquals(2, strings.size());
	}


	public void testGetInvalidStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringListClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		assertNull(claimsSet.getStringListClaim("array"));
	}


	public void testExtendedCyrillicChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet = claimsSet.withSubject("Владимир Джувинов");

		String json = claimsSet.toJSONObject().toJSONString();

		claimsSet = JWTClaimsSet.parse(json);

		assertEquals("Владимир Джувинов", claimsSet.getSubject());
	}


	public void testExtendedLatinChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet = claimsSet.withClaim("fullName", "João");

		String json = claimsSet.toJSONObject().toJSONString();

		Base64URL base64URL = Base64URL.encode(json);

		claimsSet = JWTClaimsSet.parse(base64URL.decodeToString());

		assertEquals("João", claimsSet.getStringClaim("fullName"));
	}


	public void testSerializeIgnoreNullValues() {

		JWTClaimsSet claimsSet = new JWTClaimsSet()
			.withIssuer(null)
			.withSubject(null)
			.withAudience((String)null)
			.withExpirationTime(null)
			.withIssueTime(null)
			.withNotBeforeTime(null)
			.withJWTID(null)
			.withClaim("locale", null);

		assertTrue(claimsSet.toJSONObject().isEmpty());
	}
}
