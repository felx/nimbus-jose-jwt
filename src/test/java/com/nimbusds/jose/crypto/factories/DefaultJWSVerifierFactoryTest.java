package com.nimbusds.jose.crypto.factories;


import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSProvider;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests the default JWS verifier factory.
 */
public class DefaultJWSVerifierFactoryTest extends TestCase {
	

	public void testInterfaces() {

		DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

		assertTrue(factory instanceof JWSVerifierFactory);
		assertTrue(factory instanceof JCAAware);
		assertTrue(factory instanceof JWSProvider);
	}


	public void testAlgSupport() {

		DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.HMAC_SHA));
		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.RSA));
		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.EC));
		assertEquals(JWSAlgorithm.Family.HMAC_SHA.size()
			+ JWSAlgorithm.Family.RSA.size()
			+ JWSAlgorithm.Family.EC.size()
			, factory.supportedJWSAlgorithms().size());
	}


	public void testDefaultJCAContext() {

		DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

		assertNotNull(factory.getJCAContext().getSecureRandom());
		assertNull(factory.getJCAContext().getProvider());
	}


	public void testSetSecureRandom()
		throws Exception {

		SecureRandom secureRandom = new SecureRandom() {
			@Override
			public String getAlgorithm() {
				return "test";
			}
		};

		DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
		factory.getJCAContext().setSecureRandom(secureRandom);

		KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
		SecretKey key = keyGen.generateKey();
		assertEquals(256, ByteUtils.bitLength(key.getEncoded()));

		JWSVerifier verifier = factory.createJWSVerifier(new JWSHeader(JWSAlgorithm.HS256), key);

		assertEquals("test", verifier.getJCAContext().getSecureRandom().getAlgorithm());
	}


	public void testSetProvider()
		throws Exception {

		DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
		factory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
		SecretKey key = keyGen.generateKey();
		assertEquals(256, ByteUtils.bitLength(key.getEncoded()));

		JWSVerifier verifier = factory.createJWSVerifier(new JWSHeader(JWSAlgorithm.HS256), key);

		assertEquals("BC", verifier.getJCAContext().getProvider().getName());
	}
}
