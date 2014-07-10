package com.nimbusds.jose;


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
public class PlainHeaderTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {

		PlainHeader h = new PlainHeader();

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalHeaders());
		assertNull(h.getParsedBase64URL());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalHeaders());
		assertEquals(b64url, h.getParsedBase64URL());
		assertEquals(b64url, h.toBase64URL());
	}


	public void testFullConstructor()
		throws Exception {

		Set<String> crit = new HashSet<String>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		Map<String,Object> customParams = new HashMap<String,Object>();
		customParams.put("xCustom", "abc");

		PlainHeader h = new PlainHeader(
			new JOSEObjectType("JWT"),
			"application/jwt",
			crit,
			customParams,
			null);

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("cty"));
		assertTrue(h.getIncludedParameters().contains("crit"));
		assertTrue(h.getIncludedParameters().contains("xCustom"));
		assertEquals(5, h.getIncludedParameters().size());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalHeaders().size());
		assertEquals("abc", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalHeaders().size());
		assertEquals("abc", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());
	}


	public void testBuilder()
		throws Exception {

		Set<String> crit = new HashSet<String>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		PlainHeader h = new PlainHeader.Builder().
			type(new JOSEObjectType("JWT")).
			contentType("application/jwt").
			criticalHeaders(crit).
			customParameter("xCustom", "abc").
			build();

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("cty"));
		assertTrue(h.getIncludedParameters().contains("crit"));
		assertTrue(h.getIncludedParameters().contains("xCustom"));
		assertEquals(5, h.getIncludedParameters().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalHeaders().size());
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


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<String,Object>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		PlainHeader h = new PlainHeader.Builder().
			customParameters(customParams).
			build();

		assertEquals("1", (String)h.getCustomParameter("x"));
		assertEquals("2", (String)h.getCustomParameter("y"));
		assertEquals(2, h.getCustomParameters().size());
	}
}

