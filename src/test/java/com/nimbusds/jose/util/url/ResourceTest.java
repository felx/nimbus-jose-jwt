package com.nimbusds.jose.util.url;


import junit.framework.TestCase;


public class ResourceTest extends TestCase {


	public void testWithContentType() {

		Resource resource = new Resource("content", "text/plain");
		assertEquals("content", resource.getContent());
		assertEquals("text/plain", resource.getContentType());
	}


	public void testUnspecifiedContentType() {

		Resource resource = new Resource("content", null);
		assertEquals("content", resource.getContent());
		assertNull(resource.getContentType());
	}


	public void testEmptyContent() {

		assertEquals("", new Resource("", null).getContent());
	}


	public void testRejectNullContent() {

		try {
			new Resource(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The resource content must not be null", e.getMessage());
		}
	}
}
