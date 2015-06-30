package com.nimbusds.jose;


import junit.framework.TestCase;

/**
 * Tests the JWS Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-24
 */
public class JWEAlgorithmTest extends TestCase {


	public void testParse() {

		assertEquals(JWEAlgorithm.RSA1_5, JWEAlgorithm.parse("RSA1_5"));
		assertEquals(JWEAlgorithm.RSA_OAEP, JWEAlgorithm.parse("RSA-OAEP"));

		assertEquals(JWEAlgorithm.A128KW, JWEAlgorithm.parse("A128KW"));
		assertEquals(JWEAlgorithm.A192KW, JWEAlgorithm.parse("A192KW"));
		assertEquals(JWEAlgorithm.A256KW, JWEAlgorithm.parse("A256KW"));

		assertEquals(JWEAlgorithm.DIR, JWEAlgorithm.parse("dir"));

		assertEquals(JWEAlgorithm.ECDH_ES, JWEAlgorithm.parse("ECDH-ES"));

		assertEquals(JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.parse("ECDH-ES+A128KW"));
		assertEquals(JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.parse("ECDH-ES+A192KW"));
		assertEquals(JWEAlgorithm.ECDH_ES_A256KW, JWEAlgorithm.parse("ECDH-ES+A256KW"));

		assertEquals(JWEAlgorithm.A128GCMKW, JWEAlgorithm.parse("A128GCMKW"));
		assertEquals(JWEAlgorithm.A192GCMKW, JWEAlgorithm.parse("A192GCMKW"));
		assertEquals(JWEAlgorithm.A256GCMKW, JWEAlgorithm.parse("A256GCMKW"));

		assertEquals(JWEAlgorithm.PBES2_HS256_A128KW, JWEAlgorithm.parse("PBES2-HS256+A128KW"));
		assertEquals(JWEAlgorithm.PBES2_HS384_A192KW, JWEAlgorithm.parse("PBES2-HS384+A192KW"));
		assertEquals(JWEAlgorithm.PBES2_HS512_A256KW, JWEAlgorithm.parse("PBES2-HS512+A256KW"));
	}
}
