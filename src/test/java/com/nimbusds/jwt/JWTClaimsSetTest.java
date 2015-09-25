package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2015-09-25
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

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// JWT time claim precision is seconds
		final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);

		// iss
		assertNull("iss init check", builder.build().getIssuer());
		builder.issuer("http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", builder.build().getIssuer());

		// sub
		assertNull("sub init check", builder.build().getSubject());
		builder.subject("http://subject.com");
		assertEquals("sub set check", "http://subject.com", builder.build().getSubject());

		// aud
		assertNull("aud init check", builder.build().getAudience());
		builder.audience(Arrays.asList("http://audience.com"));
		assertEquals("aud set check", "http://audience.com", builder.build().getAudience().get(0));

		// exp
		assertNull("exp init check", builder.build().getExpirationTime());
		builder.expirationTime(NOW);
		assertEquals("exp set check", NOW, builder.build().getExpirationTime());

		// nbf
		assertNull("nbf init check", builder.build().getNotBeforeTime());
		builder.notBeforeTime(NOW);
		assertEquals("nbf set check", NOW, builder.build().getNotBeforeTime());

		// iat
		assertNull("iat init check", builder.build().getIssueTime());
		builder.issueTime(NOW);
		assertEquals("iat set check", NOW, builder.build().getIssueTime());

		// jti
		assertNull("jti init check", builder.build().getJWTID());
		builder.jwtID("123");
		assertEquals("jti set check", "123", builder.build().getJWTID());

		// no custom claims
		assertEquals(7, builder.build().getClaims().size());

		// x-custom
		builder.claim("x-custom", "abc");
		assertEquals("abc", (String) builder.build().getClaim("x-custom"));


		// serialise
		JSONObject json = builder.build().toJSONObject();

		assertEquals(8, json.size());

		// parse back
		JWTClaimsSet claimsSet = null;
		try {
			claimsSet = JWTClaimsSet.parse(json);

		} catch (java.text.ParseException e) {

			fail(e.getMessage());
		}

		assertEquals("iss parse check", "http://issuer.com", claimsSet.getIssuer());
		assertEquals("sub parse check", "http://subject.com", claimsSet.getSubject());
		assertEquals("aud parse check", "http://audience.com", claimsSet.getAudience().get(0));
		assertEquals("exp parse check", NOW, claimsSet.getExpirationTime());
		assertEquals("nbf parse check", NOW, claimsSet.getNotBeforeTime());
		assertEquals("iat parse check", NOW, claimsSet.getIssueTime());
		assertEquals("jti parse check", "123", claimsSet.getJWTID());
		assertEquals("abc", (String)claimsSet.getClaim("x-custom"));
		assertEquals(8, claimsSet.getClaims().size());


		Map<String,Object> all = claimsSet.getClaims();

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

		final Date ONE_MIN_AFTER_EPOCH = new Date(1000*60);

		JWTClaimsSet cs = new JWTClaimsSet.Builder()
			.issueTime(ONE_MIN_AFTER_EPOCH)
			.notBeforeTime(ONE_MIN_AFTER_EPOCH)
			.expirationTime(ONE_MIN_AFTER_EPOCH)
			.build();

		JSONObject json = cs.toJSONObject();

		assertEquals(new Long(60l), json.get("iat"));
		assertEquals(new Long(60l), json.get("nbf"));
		assertEquals(new Long(60l), json.get("exp"));
	}
	
	
	public void testCustomClaim() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder().claim("locale", "bg-BG").build();
		assertEquals(1, cs.getClaims().size());

		cs = new JWTClaimsSet.Builder().claim("locale", null).build();
		assertNull(cs.getClaim("locale"));
		assertEquals(1, cs.getClaims().size());
	}


	public void testNullCustomClaim() {

		JWTClaimsSet cs = new JWTClaimsSet.Builder().claim("locale", null).build();
		assertNull(cs.getClaim("locale"));
		assertEquals(1, cs.getClaims().size());
	}
	
	
	public void testSetCustomClaims() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder()
			.claim("locale", "bg-BG")
			.claim("locale", "es-ES")
			.claim("ip", "127.0.0.1")
			.build();

		assertEquals(2, cs.getClaims().size());
		
		assertEquals("es-ES", (String)cs.getClaims().get("locale"));
		assertEquals("127.0.0.1", (String)cs.getClaims().get("ip"));
	}
	
	
	public void testGetClaimValueNotSpecified() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder().build();
		
		assertNull(cs.getClaim("xyz"));
	}
	
	
	public void testSetClaimNull() {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.issuer("http://example.com");
		assertEquals("http://example.com", builder.build().getIssuer());
		builder = builder.claim("iss", null);
		assertNull(builder.build().getIssuer());
		
		builder.subject("alice");
		assertEquals("alice", builder.build().getSubject());
		builder.claim("sub", null);
		assertNull(builder.build().getSubject());
		
		List<String> audList = new ArrayList<>();
		audList.add("http://client.example.com");
		builder.audience(audList);
		assertEquals("http://client.example.com", builder.build().getAudience().get(0));
		builder = builder.claim("aud", null);
		assertNull(builder.build().getAudience());
		
		Date now = new Date();
		builder.expirationTime(now);
		assertEquals(now, builder.build().getExpirationTime());
		builder = builder.claim("exp", null);
		assertNull(builder.build().getExpirationTime());
		
		builder.notBeforeTime(now);
		assertEquals(now, builder.build().getNotBeforeTime());
		builder = builder.claim("nbf", null);
		assertNull(builder.build().getNotBeforeTime());
		
		builder.issueTime(now);
		assertEquals(now, builder.build().getIssueTime());
		builder = builder.claim("iat", null);
		assertNull(builder.build().getIssueTime());
		
		builder.jwtID("123");
		assertEquals("123", builder.build().getJWTID());
		builder = builder.claim("jti", null);
		assertNull(builder.build().getJWTID());
	}
	
	
	public void testGetClaimTyped()
		throws Exception {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", "abc");
		assertEquals("abc", builder.build().getStringClaim("string"));
		
		builder.claim("boolean", false);
		assertFalse(builder.build().getBooleanClaim("boolean"));
		
		builder.claim("integer", 123);
		assertEquals(123, builder.build().getIntegerClaim("integer").intValue());
		
		builder.claim("long", 456l);
		assertEquals(456l, builder.build().getLongClaim("long").longValue());

		Date date = new Date(999000l);
		builder.claim("date", date);
		assertEquals(date, builder.build().getDateClaim("date"));

		// Convert Unix timestamp to Java date
		builder.claim("date-long", 999l);
		assertEquals(new Date(999000l), builder.build().getDateClaim("date-long"));
		
		builder.claim("float", 3.14f);
		assertEquals(3.14f, builder.build().getFloatClaim("float").floatValue());
		
		builder.claim("double", 3.14d);
		assertEquals(3.14d, builder.build().getDoubleClaim("double").doubleValue());
	}
	
	
	public void testGetClaimTypedNull()
		throws Exception {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", null);
		assertNull(builder.build().getStringClaim("string"));
		
		builder.claim("boolean", null);
		assertNull(builder.build().getBooleanClaim("boolean"));
		
		builder.claim("integer", null);
		assertNull(builder.build().getIntegerClaim("integer"));
		
		builder.claim("long", null);
		assertNull(builder.build().getLongClaim("long"));
		
		builder.claim("date", null);
		assertNull(builder.build().getDateClaim("date"));
		
		builder.claim("float", null);
		assertNull(builder.build().getFloatClaim("float"));
		
		builder.claim("double", null);
		assertNull(builder.build().getDoubleClaim("double"));
	}
	
	
	public void testGetClaimTypedParseException() {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", 3.14);
		
		try {
			builder.build().getStringClaim("string");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("boolean", "123");
		
		try {
			builder.build().getBooleanClaim("boolean");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("integer", true);
		
		try {
			builder.build().getIntegerClaim("integer");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("long", "abc");
		
		try {
			builder.build().getLongClaim("long");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("date", "abc");
		
		try {
			builder.build().getDateClaim("date");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("float", true);
		
		try {
			builder.build().getFloatClaim("float");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("double", "abc");
		
		try {
			builder.build().getDoubleClaim("double");
			
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

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
		assertNull(claimsSet.getAudience());

		claimsSet = new JWTClaimsSet.Builder().audience("123").build();
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());

		claimsSet = new JWTClaimsSet.Builder().audience((String) null).build();
		assertNull(claimsSet.getAudience());
	}


	public void testSerializeSingleValuedAudience()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience("123").build();

		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals("123", (String)jsonObject.get("aud"));
		assertEquals(1, jsonObject.size());

		claimsSet = JWTClaimsSet.parse(jsonObject.toJSONString());
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());
	}


	public void testGetAllClaimsEmpty() {

		assertTrue(new JWTClaimsSet.Builder().build().getClaims().isEmpty());
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

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("Владимир Джувинов").build();

		String json = claimsSet.toJSONObject().toJSONString();

		claimsSet = JWTClaimsSet.parse(json);

		assertEquals("Владимир Джувинов", claimsSet.getSubject());
	}


	public void testExtendedLatinChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("fullName", "João").build();

		String json = claimsSet.toJSONObject().toJSONString();

		Base64URL base64URL = Base64URL.encode(json);

		claimsSet = JWTClaimsSet.parse(base64URL.decodeToString());

		assertEquals("João", claimsSet.getStringClaim("fullName"));
	}


	public void testSerializeIgnoreNullValues() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(null)
			.subject(null)
			.audience((String)null)
			.expirationTime(null)
			.issueTime(null)
			.notBeforeTime(null)
			.jwtID(null)
			.claim("locale", null)
			.build();

		assertTrue(claimsSet.toJSONObject().isEmpty());
	}


	public void testTransformer() {

		JWTClaimsSetTransformer<String> transformer = new JWTClaimsSetTransformer<String>() {
			@Override
			public String transform(JWTClaimsSet claimsSet) {
				return claimsSet.getSubject();
			}
		};

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();

		assertEquals("alice", claimsSet.toType(transformer));
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testParseListOfStrings()
		throws ParseException {

		String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		assertEquals("HS256", claimsSet.getStringClaim("alg"));

		List<String> audList = claimsSet.getStringListClaim("aud");
		assertEquals("a", audList.get(0));
		assertEquals("b", audList.get(1));
		assertEquals(2, audList.size());

		List<String> testList = claimsSet.getStringListClaim("test");
		assertEquals("a", testList.get(0));
		assertEquals("b", testList.get(1));
		assertEquals(2, testList.size());

		assertEquals(3, claimsSet.getClaims().size());
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testListOfStrings() {

		List<String> audList = new LinkedList<>();
		audList.add("a");
		audList.add("b");

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("aud", audList)
			.build();

		assertEquals("{\"aud\":[\"a\",\"b\"]}", claimsSet.toJSONObject().toString());
	}
}
