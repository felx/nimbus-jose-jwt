package com.nimbusds.jose;


import java.net.URL;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
public class JWSHeaderTest extends TestCase {


	public void testMinimalConstructor() {

		JWSHeader h = new JWSHeader(JWSAlgorithm.HS256);

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getJWKURL());
		assertNull(h.getJWK());
		assertNull(h.getX509CertURL());
		assertNull(h.getX509CertThumbprint());
		assertNull(h.getX509CertChain());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalHeaders());
		assertTrue(h.getCustomParameters().isEmpty());
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

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));

		System.out.println("Included parameters: " + h.getIncludedParameters());

		assertEquals(2, h.getIncludedParameters().size());
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

		Set<String> crit = new HashSet<String>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.RS256).
			criticalHeaders(crit).
			build();

		assertEquals(3, h.getCriticalHeaders().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWSHeader.parse(b64url);
		
		crit = h.getCriticalHeaders();

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
			type(JOSEObjectType.JWS).
			contentType("application/json").
			criticalHeaders(new HashSet<String>(Arrays.asList("exp", "nbf"))).
			jwkURL(new URL("http://example.com/jwk.json")).
			jwk(new OctetSequenceKey.Builder(new Base64URL("xyz")).build()).
			x509CertURL(new URL("http://example.com/cert.pem")).
			x509CertThumbprint(new Base64URL("abc")).
			x509CertChain(Arrays.asList(new Base64("abc"), new Base64("def"))).
			keyID("123").
			customParameter("exp", 123).
			customParameter("nbf", 456).
			build();

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertEquals(JOSEObjectType.JWS, h.getType());
		assertEquals("application/json", h.getContentType());
		assertTrue(h.getCriticalHeaders().contains("exp"));
		assertTrue(h.getCriticalHeaders().contains("nbf"));
		assertEquals(2, h.getCriticalHeaders().size());
		assertEquals("http://example.com/jwk.json", h.getJWKURL().toString());
		assertEquals("xyz", ((OctetSequenceKey)h.getJWK()).getKeyValue().toString());
		assertEquals("http://example.com/cert.pem", h.getX509CertURL().toString());
		assertEquals("abc", h.getX509CertThumbprint().toString());
		assertEquals("abc", h.getX509CertChain().get(0).toString());
		assertEquals("def", h.getX509CertChain().get(1).toString());
		assertEquals(2, h.getX509CertChain().size());
		assertEquals("123", h.getKeyID());
		assertEquals(123, ((Integer)h.getCustomParameter("exp")).intValue());
		assertEquals(456, ((Integer)h.getCustomParameter("nbf")).intValue());
		assertEquals(2, h.getCustomParameters().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("cty"));
		assertTrue(h.getIncludedParameters().contains("crit"));
		assertTrue(h.getIncludedParameters().contains("jku"));
		assertTrue(h.getIncludedParameters().contains("jwk"));
		assertTrue(h.getIncludedParameters().contains("x5u"));
		assertTrue(h.getIncludedParameters().contains("x5t"));
		assertTrue(h.getIncludedParameters().contains("x5c"));
		assertTrue(h.getIncludedParameters().contains("kid"));
		assertTrue(h.getIncludedParameters().contains("exp"));
		assertTrue(h.getIncludedParameters().contains("nbf"));
		assertEquals(12, h.getIncludedParameters().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<String,Object>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParameters(customParams).
			build();

		assertEquals("1", (String)h.getCustomParameter("x"));
		assertEquals("2", (String)h.getCustomParameter("y"));
		assertEquals(2, h.getCustomParameters().size());
	}


	public void testImmutableCustomParams() {

		Map<String,Object> customParams = new HashMap<String,Object>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParameters(customParams).
			build();

		try {
			h.getCustomParameters().put("x", "3");
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}


	public void testImmutableCritHeaders() {

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			criticalHeaders(new HashSet<String>(Arrays.asList("exp", "nbf"))).
			build();

		try {
			h.getCriticalHeaders().remove("exp");
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}
}

