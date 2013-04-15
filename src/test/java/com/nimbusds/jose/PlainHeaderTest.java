package com.nimbusds.jose;


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-15)
 */
public class PlainHeaderTest extends TestCase {


	public void testSerializeAndParse()
		throws Exception {

		PlainHeader h = new PlainHeader();

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());


		h.setType(new JOSEObjectType("JWT"));
		h.setContentType("application/jwt");
		h.setCustomParameter("xCustom", "abc");

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("cty"));
		assertTrue(h.getIncludedParameters().contains("xCustom"));
		assertEquals(4, h.getIncludedParameters().size());


		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals("abc", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());
	}


	public void testParseExample()
		throws Exception {

		// Example BASE64URL from JWT spec
		Base64URL in = new Base64URL("eyJhbGciOiJub25lIn0");

		PlainHeader header = PlainHeader.parse(in);

		assertEquals(in, header.toBase64URL());

		assertEquals(Algorithm.NONE, header.getAlgorithm());
	}
}

