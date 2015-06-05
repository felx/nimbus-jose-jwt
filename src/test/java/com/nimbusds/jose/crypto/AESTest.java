package com.nimbusds.jose.crypto;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import java.security.Provider;
import java.security.SecureRandom;


/**
 * Tests the AES utility class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-06)
 */
public class AESTest extends TestCase {


	public void testKeyGenerator()
		throws Exception {

		KeyGenerator keyGenerator = AES.createKeyGenerator(null);
		assertEquals("AES", keyGenerator.getAlgorithm());
	}


	public void testGenerateKeys()
		throws Exception {

		testGenerateKey(128, null);
		testGenerateKey(192, null);
		testGenerateKey(256, null);

		// Default Sun JCA provider supports up to 256 bit AES keys generation
		testGenerateKey(512, BouncyCastleProviderSingleton.getInstance());
		testGenerateKey(1024, BouncyCastleProviderSingleton.getInstance());
	}


	private void testGenerateKey(final int bitLength, final Provider provider)
		throws Exception {

		SecretKey aesKey = AES.generateKey(bitLength, provider, new SecureRandom());

		assertEquals("AES", aesKey.getAlgorithm());
		assertEquals(bitLength / 8, aesKey.getEncoded().length);
		assertEquals("RAW", aesKey.getFormat());
	}
}
