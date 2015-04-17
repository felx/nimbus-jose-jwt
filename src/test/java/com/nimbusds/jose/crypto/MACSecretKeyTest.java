package com.nimbusds.jose.crypto;


import java.util.Arrays;

import junit.framework.TestCase;


/**
 * Tests the MAC secret key.
 */
public class MACSecretKeyTest extends TestCase {


	public void testBytes() {

		byte[] bytes = {0, 1, 2, 3};

		MACSecretKey key = new MACSecretKey(bytes);

		assertTrue(Arrays.equals(bytes, key.getEncoded()));
	}


	public void testAlgorithm() {

		MACSecretKey key = new MACSecretKey(new byte[]{0, 1, 2, 3});

		assertEquals("MAC", key.getAlgorithm());
	}


	public void testFormat() {

		MACSecretKey key = new MACSecretKey(new byte[]{0, 1, 2, 3});

		assertNull(key.getFormat());
	}
}
