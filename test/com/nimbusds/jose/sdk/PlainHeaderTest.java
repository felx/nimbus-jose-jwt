package com.nimbusds.jose.sdk;


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
public class PlainHeaderTest extends TestCase {
	
	
	public void testSerializeAndParse() {
	
		PlainHeader h = new PlainHeader();
		
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		
		
		h.setType(new JOSEObjectType("JWT"));
		h.setContentType("application/jwt");
		h.setCustomParameter("xCustom", "abc");
		
		
		Base64URL b64url = h.toBase64URL();
		
		// Parse back
		
		try {
			h = PlainHeader.parse(b64url);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals("abc", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());
	}
}

