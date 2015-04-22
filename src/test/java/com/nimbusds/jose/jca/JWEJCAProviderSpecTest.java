package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the JWE JCA provider spec.
 */
public class JWEJCAProviderSpecTest extends TestCase {


	public void testDefaultConstructor() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec();

		assertNull(spec.getProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testConstructorAllNullArgs() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec(null, null, null, null, null);

		assertNull(spec.getProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testSettersAllNull() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec();

		spec = spec.withProvider(null);
		spec = spec.withKeyEncryptionProvider(null);
		spec = spec.withContentEncryptionProvider(null);
		spec = spec.withMACProvider(null);
		spec = spec.withSecureRandom(null);

		assertNull(spec.getProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testSetSecureRandom() {

		SecureRandom sr = new SecureRandom();

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec().withSecureRandom(sr);

		assertEquals(sr, spec.getSecureRandom());
	}


	public void testSetProvider() {

		Provider provider = new Provider("c2id", 1.0, "test") { };

		assertEquals("c2id", provider.getName());
		assertEquals(1.0, provider.getVersion());
		assertEquals("test", provider.getInfo());

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec();

		spec = spec.withProvider(provider);
		spec = spec.withKeyEncryptionProvider(provider);
		spec = spec.withContentEncryptionProvider(provider);
		spec = spec.withMACProvider(provider);

		assertEquals(provider, spec.getProvider());
		assertEquals(provider, spec.getKeyEncryptionProvider());
		assertEquals(provider, spec.getContentEncryptionProvider());
		assertEquals(provider, spec.getMACProvider());
	}
}
