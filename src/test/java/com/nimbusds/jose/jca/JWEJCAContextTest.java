package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the JWE JCA context.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-02)
 */
public class JWEJCAContextTest extends TestCase {


	public void testDefaultConstructor() {

		JWEJCAContext spec = new JWEJCAContext();

		assertNull(spec.getProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testConstructorAllNullArgs() {

		JWEJCAContext spec = new JWEJCAContext(null, null, null, null, null);

		assertNull(spec.getProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testSettersAllNull() {

		JWEJCAContext spec = new JWEJCAContext();

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

		JWEJCAContext spec = new JWEJCAContext().withSecureRandom(sr);

		assertEquals(sr, spec.getSecureRandom());
	}


	public void testSetGeneralAndSpecificProviders() {

		JWEJCAContext spec = new JWEJCAContext().
			withProvider(new Provider("general", 1.0, "test") {
			}).
			withKeyEncryptionProvider(new Provider("ke", 1.0, "test") { }).
			withContentEncryptionProvider(new Provider("ce", 1.0, "test") { }).
			withMACProvider(new Provider("mac", 1.0, "test") { });

		assertEquals("general", spec.getProvider().getName());
		assertEquals("ke", spec.getKeyEncryptionProvider().getName());
		assertEquals("ce", spec.getContentEncryptionProvider().getName());
		assertEquals("mac", spec.getMACProvider().getName());
	}


	public void testFallbackToGeneralProvider() {

		Provider provider = new Provider("general", 1.0, "test") { };

		JWEJCAContext spec = new JWEJCAContext().withProvider(provider);

		assertEquals(provider, spec.getProvider());
		assertEquals(provider, spec.getKeyEncryptionProvider());
		assertEquals(provider, spec.getContentEncryptionProvider());
		assertEquals(provider, spec.getMACProvider());
	}
}
