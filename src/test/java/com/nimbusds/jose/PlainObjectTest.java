package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests plaintext JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-07-15)
 */
public class PlainObjectTest extends TestCase {


	public void testSerializeAndParse()
		throws Exception {

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

		p = PlainObject.parse(serializedJOSEObject);

		h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParameters().isEmpty());

		assertEquals("Hello world!", p.getPayload().toString());

		assertEquals(serializedJOSEObject, p.getParsedString());
	}
}
