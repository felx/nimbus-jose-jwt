package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the JWT Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
 */
public class JWSAlgorithmTest extends TestCase {


	public void testParse() {

		assertEquals(JWSAlgorithm.HS256, JWSAlgorithm.parse("HS256"));
		assertEquals(JWSAlgorithm.HS384, JWSAlgorithm.parse("HS384"));
		assertEquals(JWSAlgorithm.HS512, JWSAlgorithm.parse("HS512"));

		assertEquals(JWSAlgorithm.RS256, JWSAlgorithm.parse("RS256"));
		assertEquals(JWSAlgorithm.RS384, JWSAlgorithm.parse("RS384"));
		assertEquals(JWSAlgorithm.RS512, JWSAlgorithm.parse("RS512"));

		assertEquals(JWSAlgorithm.ES256, JWSAlgorithm.parse("ES256"));
		assertEquals(JWSAlgorithm.ES384, JWSAlgorithm.parse("ES384"));
		assertEquals(JWSAlgorithm.ES512, JWSAlgorithm.parse("ES512"));

		assertEquals(JWSAlgorithm.PS256, JWSAlgorithm.parse("PS256"));
		assertEquals(JWSAlgorithm.PS384, JWSAlgorithm.parse("PS384"));
		assertEquals(JWSAlgorithm.PS512, JWSAlgorithm.parse("PS512"));
	}
}
