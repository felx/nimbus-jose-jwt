package com.nimbusds.jose.crypto;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;


/**
 * Tests the AES utility class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-10-16)
 */
public class AESTest extends TestCase {


	public void testKeyGenerator()
		throws Exception {

		KeyGenerator keyGenerator = AES.createKeyGenerator();

		assertEquals("AES", keyGenerator.getAlgorithm());
	}


	public void testGenerateKeys()
		throws Exception {

		testGenerateKey(128);

		testGenerateKey(256);

		testGenerateKey(512);

		testGenerateKey(1024);
	}


	private void testGenerateKey(final int bitLength)
		throws Exception {

		SecretKey aesKey = AES.generateKey(bitLength);

		assertEquals("AES", aesKey.getAlgorithm());
		assertEquals(bitLength / 8, aesKey.getEncoded().length);
		assertEquals("RAW", aesKey.getFormat());
	}
}
