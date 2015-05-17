package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the JWE JCA provider spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-16)
 */
public class JWEJCAProviderSpecTest extends TestCase {


	public void testDefaultConstructor() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec();

		assertNull(spec.getGeneralProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testConstructorAllNullArgs() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec(null, null, null, null, null);

		assertNull(spec.getGeneralProvider());
		assertNull(spec.getKeyEncryptionProvider());
		assertNull(spec.getContentEncryptionProvider());
		assertNull(spec.getMACProvider());
		assertNotNull(spec.getSecureRandom());
	}


	public void testSettersAllNull() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec();

		spec = spec.withGeneralProvider(null);
		spec = spec.withKeyEncryptionProvider(null);
		spec = spec.withContentEncryptionProvider(null);
		spec = spec.withMACProvider(null);
		spec = spec.withSecureRandom(null);

		assertNull(spec.getGeneralProvider());
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


	public void testSetGeneralAndSpecificProviders() {

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec().
			withGeneralProvider(new Provider("general", 1.0, "test") {
			}).
			withKeyEncryptionProvider(new Provider("ke", 1.0, "test") { }).
			withContentEncryptionProvider(new Provider("ce", 1.0, "test") { }).
			withMACProvider(new Provider("mac", 1.0, "test") { });

		assertEquals("general", spec.getGeneralProvider().getName());
		assertEquals("ke", spec.getKeyEncryptionProvider().getName());
		assertEquals("ce", spec.getContentEncryptionProvider().getName());
		assertEquals("mac", spec.getMACProvider().getName());
	}


	public void testFallbackToGeneralProvider() {

		Provider provider = new Provider("general", 1.0, "test") { };

		JWEJCAProviderSpec spec = new JWEJCAProviderSpec().withGeneralProvider(provider);

		assertEquals(provider, spec.getGeneralProvider());
		assertEquals(provider, spec.getKeyEncryptionProvider());
		assertEquals(provider, spec.getContentEncryptionProvider());
		assertEquals(provider, spec.getMACProvider());
	}
}
