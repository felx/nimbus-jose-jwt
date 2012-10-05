package com.nimbusds.jose;


import java.text.ParseException;

import junit.framework.TestCase;


/**
 * Tests plain JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
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
		
		try {
			p = PlainObject.parse(p.serialize());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		assertEquals("Hello world!", p.getPayload().toString());
	}
}
