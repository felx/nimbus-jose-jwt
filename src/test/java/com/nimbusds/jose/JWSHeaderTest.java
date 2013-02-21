package com.nimbusds.jose;


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-01)
 */
public class JWSHeaderTest extends TestCase {


	public void testParseJSONText() {

		// Example header from JWS spec

		String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

		JWSHeader h = null;

		try {
			h = JWSHeader.parse(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertNotNull(h);

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertEquals(2, h.getIncludedParameters().size());
	}


	public void testParseBase64URLText() {

		// Example header from JWS spec

		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

		JWSHeader h = null;

		try {
			h = JWSHeader.parse(new Base64URL(s));

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertNotNull(h);

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());
	}
}

