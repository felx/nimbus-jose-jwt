package com.nimbusds.jose.jwk;


import junit.framework.TestCase;


/**
 * Tests the base JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-02-04
 */
public class JWKTest extends TestCase {

	public void testMIMEType() {

		assertEquals("application/jwk+json; charset=UTF-8", JWK.MIME_TYPE);
	}
}
