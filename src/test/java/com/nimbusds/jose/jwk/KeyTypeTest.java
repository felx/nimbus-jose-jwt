package com.nimbusds.jose.jwk;


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
}
