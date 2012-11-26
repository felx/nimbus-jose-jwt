package com.nimbusds.jose;


import java.text.ParseException;

import junit.framework.TestCase;


/**
 * Tests plaintext JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
public class PlainObjectTest extends TestCase {
	

	public void testSerializeAndParse() {

		Payload payload = new Payload("Hello world!");

		PlainObject p = new PlainObject(payload);
		
		assertNotNull(p.getHeader());
		assertEquals("Hello world!", p.getPayload().toString());
		
		ReadOnlyPlainHeader h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParameters().isEmpty());

		String serializedJOSEObject = p.serialize();
		
		try {
			p = PlainObject.parse(serializedJOSEObject);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		assertEquals("Hello world!", p.getPayload().toString());

		assertEquals(serializedJOSEObject, p.getParsedString());
	}
}
