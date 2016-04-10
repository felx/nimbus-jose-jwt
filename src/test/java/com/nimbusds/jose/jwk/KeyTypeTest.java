package com.nimbusds.jose.jwk;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import junit.framework.TestCase;

import com.nimbusds.jose.Requirement;


/**
 * Tests the key type class.
 */
public class KeyTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("RSA", KeyType.RSA.getValue());
		assertEquals(Requirement.REQUIRED, KeyType.RSA.getRequirement());

		assertEquals("EC", KeyType.EC.getValue());
		assertEquals(Requirement.RECOMMENDED, KeyType.EC.getRequirement());

		assertEquals("oct", KeyType.OCT.getValue());
		assertEquals(Requirement.OPTIONAL, KeyType.OCT.getRequirement());
	}


	public void testInferForAlgorithm() {

		assertNull(KeyType.forAlgorithm(null));

		assertNull(KeyType.forAlgorithm(Algorithm.NONE));

		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.RS256));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.RS384));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.RS512));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.PS256));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.PS384));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWSAlgorithm.PS512));

		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWSAlgorithm.ES256));
		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWSAlgorithm.ES384));
		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWSAlgorithm.ES512));

		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWSAlgorithm.HS256));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWSAlgorithm.HS384));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWSAlgorithm.HS512));

		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWEAlgorithm.RSA1_5));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWEAlgorithm.RSA_OAEP));
		assertEquals(KeyType.RSA, KeyType.forAlgorithm(JWEAlgorithm.RSA_OAEP_256));

		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWEAlgorithm.ECDH_ES));
		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWEAlgorithm.ECDH_ES_A128KW));
		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWEAlgorithm.ECDH_ES_A192KW));
		assertEquals(KeyType.EC, KeyType.forAlgorithm(JWEAlgorithm.ECDH_ES_A256KW));

		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.DIR));

		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A128KW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A192KW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A256KW));

		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A128GCMKW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A192GCMKW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.A256GCMKW));

		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.PBES2_HS256_A128KW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.PBES2_HS384_A192KW));
		assertEquals(KeyType.OCT, KeyType.forAlgorithm(JWEAlgorithm.PBES2_HS512_A256KW));

		assertNull(KeyType.forAlgorithm(new Algorithm("custom")));
	}
}
