package com.nimbusds.jose;


import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-10-08)
 */
public class JWSHeaderTest extends TestCase {


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

		JWSHeader h = new JWSHeader(JWSAlgorithm.RS256);

		Set<String> crit = new HashSet<String>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		assertNull(h.getCriticalHeaders());

		h.setCriticalHeaders(crit);

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
}

