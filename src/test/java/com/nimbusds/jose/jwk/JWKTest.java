package com.nimbusds.jose.jwk;


import junit.framework.TestCase;


/**
 * Tests the JSON Web Key (JWK) class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-29)
 */
public class JWKTest extends TestCase {

	public void testMIMETypes()
		throws Exception {

		assertTrue(JWKSet.MIME_TYPE.match("application/jwk-set+json"));
		assertTrue(JWKSet.MIME_TYPE.getParameterList().get("charset").equalsIgnoreCase("UTF-8"));
		assertEquals(1, JWKSet.MIME_TYPE.getParameterList().size());
	}
}