package com.nimbusds.jose.util;


import junit.framework.TestCase;


public class StandardCharsetTest extends TestCase {
	

	public void testConstant() {
		
		assertEquals("UTF-8", StandardCharset.UTF_8.name());
	}
}
