/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose;


import java.net.URI;
import java.text.ParseException;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import net.minidev.json.JSONObject;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-01-10
 */
public class JWSHeaderTest extends TestCase {


	public void testMinimalConstructor() {

		JWSHeader h = new JWSHeader(JWSAlgorithm.HS256);

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getJWKURL());
		assertNull(h.getJWK());
		assertNull(h.getX509CertURL());
		assertNull(h.getX509CertThumbprint());
		assertNull(h.getX509CertSHA256Thumbprint());
		assertNull(h.getX509CertChain());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertTrue(h.getCustomParams().isEmpty());
	}


	public void testSerializeAndParse()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final KeyUse use = KeyUse.ENCRYPTION;
		final String kid = "1234";

		RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA1_5).keyID(kid).build();

		List<Base64> certChain = new LinkedList<>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.RS256).
			type(new JOSEObjectType("JWT")).
			contentType("application/json").
			criticalParams(crit).
			jwkURL(new URI("https://example.com/jku.json")).
			jwk(jwk).
			x509CertURL(new URI("https://example/cert.b64")).
			x509CertThumbprint(new Base64URL("789iop")).
			x509CertSHA256Thumbprint(new Base64URL("789asd")).
			x509CertChain(certChain).
			keyID("1234").
			customParam("xCustom", "+++").
			build();


		Base64URL base64URL = h.toBase64URL();

		// Parse back
		h = JWSHeader.parse(base64URL);

		assertEquals(JWSAlgorithm.RS256, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertTrue(h.getCriticalParams().contains("iat"));
		assertTrue(h.getCriticalParams().contains("exp"));
		assertTrue(h.getCriticalParams().contains("nbf"));
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("application/json", h.getContentType());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("cty"));
		assertTrue(h.getIncludedParams().contains("crit"));
		assertTrue(h.getIncludedParams().contains("jku"));
		assertTrue(h.getIncludedParams().contains("jwk"));
		assertTrue(h.getIncludedParams().contains("kid"));
		assertTrue(h.getIncludedParams().contains("x5u"));
		assertTrue(h.getIncludedParams().contains("x5t"));
		assertTrue(h.getIncludedParams().contains("x5c"));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(12, h.getIncludedParams().size());

		// Test copy constructor
		h = new JWSHeader(h);

		assertEquals(JWSAlgorithm.RS256, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertTrue(h.getCriticalParams().contains("iat"));
		assertTrue(h.getCriticalParams().contains("exp"));
		assertTrue(h.getCriticalParams().contains("nbf"));
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("application/json", h.getContentType());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());
	}


	public void testParseJSONText()
		throws Exception {

		// Example header from JWS spec

		String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

		JWSHeader h = JWSHeader.parse(s);

		assertNotNull(h);

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertEquals(2, h.getIncludedParams().size());
	}


	public void testParseBase64URLText()
		throws Exception {

		// Example header from JWS spec

		Base64URL in = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

		JWSHeader h = JWSHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());
	}


	public void testCrit()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.RS256).
			criticalParams(crit).
			build();

		assertEquals(3, h.getCriticalParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWSHeader.parse(b64url);
		
		crit = h.getCriticalParams();

		assertTrue(crit.contains("iat"));
		assertTrue(crit.contains("exp"));
		assertTrue(crit.contains("nbf"));

		assertEquals(3, crit.size());
	}


	public void testRejectNone() {

		try {
			new JWSHeader(new JWSAlgorithm("none"));

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testBuilder()
		throws Exception {

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			type(JOSEObjectType.JOSE).
			contentType("application/json").
			criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
			jwkURL(new URI("http://example.com/jwk.json")).
			jwk(new OctetSequenceKey.Builder(new Base64URL("xyz")).build()).
			x509CertURL(new URI("http://example.com/cert.pem")).
			x509CertThumbprint(new Base64URL("abc")).
			x509CertSHA256Thumbprint(new Base64URL("abc256")).
			x509CertChain(Arrays.asList(new Base64("abc"), new Base64("def"))).
			keyID("123").
			customParam("exp", 123).
			customParam("nbf", 456).
			build();

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertEquals(JOSEObjectType.JOSE, h.getType());
		assertEquals("application/json", h.getContentType());
		assertTrue(h.getCriticalParams().contains("exp"));
		assertTrue(h.getCriticalParams().contains("nbf"));
		assertEquals(2, h.getCriticalParams().size());
		assertEquals("http://example.com/jwk.json", h.getJWKURL().toString());
		assertEquals("xyz", ((OctetSequenceKey)h.getJWK()).getKeyValue().toString());
		assertEquals("http://example.com/cert.pem", h.getX509CertURL().toString());
		assertEquals("abc", h.getX509CertThumbprint().toString());
		assertEquals("abc256", h.getX509CertSHA256Thumbprint().toString());
		assertEquals("abc", h.getX509CertChain().get(0).toString());
		assertEquals("def", h.getX509CertChain().get(1).toString());
		assertEquals(2, h.getX509CertChain().size());
		assertEquals("123", h.getKeyID());
		assertEquals(123, ((Integer)h.getCustomParam("exp")).intValue());
		assertEquals(456, ((Integer)h.getCustomParam("nbf")).intValue());
		assertEquals(2, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("cty"));
		assertTrue(h.getIncludedParams().contains("crit"));
		assertTrue(h.getIncludedParams().contains("jku"));
		assertTrue(h.getIncludedParams().contains("jwk"));
		assertTrue(h.getIncludedParams().contains("x5u"));
		assertTrue(h.getIncludedParams().contains("x5t"));
		assertTrue(h.getIncludedParams().contains("x5c"));
		assertTrue(h.getIncludedParams().contains("kid"));
		assertTrue(h.getIncludedParams().contains("exp"));
		assertTrue(h.getIncludedParams().contains("nbf"));
		assertEquals(13, h.getIncludedParams().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
	}


	public void testImmutableCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParams(customParams).
			build();

		try {
			h.getCustomParams().put("x", "3");
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}


	public void testImmutableCritHeaders() {

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
			build();

		try {
			h.getCriticalParams().remove("exp");
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testParseCustomParamListOfStrings()
		throws ParseException {

		String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

		JWSHeader header = JWSHeader.parse(json);

		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());

		List<?> audList = (List)header.getCustomParam("aud");
		assertEquals("a", audList.get(0));
		assertEquals("b", audList.get(1));
		assertEquals(2, audList.size());

		List<?> testList = (List)header.getCustomParam("test");
		assertEquals("a", testList.get(0));
		assertEquals("b", testList.get(1));
		assertEquals(2, testList.size());
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testSetCustomParamListOfStrings() {

		List<String> audList = new LinkedList<>();
		audList.add("a");
		audList.add("b");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("aud", audList)
			.build();

		assertTrue(header.toJSONObject().toJSONString().contains("\"aud\":[\"a\",\"b\"]"));
	}
	
	
	// iss #208
	public void testHeaderParameterAsJSONObject()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", "value");
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("prm", jsonObject)
			.build();
		
		jsonObject = (JSONObject) header.getCustomParam("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		JSONObject headerJSONObject = header.toJSONObject();
		assertEquals("HS256", headerJSONObject.get("alg"));
		jsonObject = (JSONObject) headerJSONObject.get("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		assertEquals(2, headerJSONObject.size());
		
		Base64URL encodedHeader = header.toBase64URL();
		
		header = JWSHeader.parse(encodedHeader);
		
		jsonObject = (JSONObject) header.getCustomParam("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		headerJSONObject = header.toJSONObject();
		assertEquals("HS256", headerJSONObject.get("alg"));
		jsonObject = (JSONObject) headerJSONObject.get("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		assertEquals(2, headerJSONObject.size());
	}
}

