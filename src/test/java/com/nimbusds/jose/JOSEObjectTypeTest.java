package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the JOSE object type header parmeter.
 */
public class JOSEObjectTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("JOSE", JOSEObjectType.JOSE.getType());
		assertEquals("JOSE+JSON", JOSEObjectType.JOSE_JSON.getType());
		assertEquals("JWT", JOSEObjectType.JWT.getType());
	}


	public void testToString() {

		assertEquals(JOSEObjectType.JOSE.getType(), JOSEObjectType.JOSE.toString());
		assertEquals(JOSEObjectType.JOSE_JSON.getType(), JOSEObjectType.JOSE_JSON.toString());
		assertEquals(JOSEObjectType.JWT.getType(), JOSEObjectType.JWT.toString());
	}


	public void testJSONAware() {

		assertEquals("\"JWT\"", JOSEObjectType.JWT.toJSONString());
	}
}
