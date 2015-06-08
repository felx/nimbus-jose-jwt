package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the JWE JCA context.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
public class JWEJCAContextTest extends TestCase {


	public void testDefaultConstructor() {

		JWEJCAContext ctx = new JWEJCAContext();

		assertNull(ctx.getProvider());
		assertNull(ctx.getKeyEncryptionProvider());
		assertNull(ctx.getContentEncryptionProvider());
		assertNull(ctx.getMACProvider());
		assertNotNull(ctx.getSecureRandom());
	}


	public void testConstructorAllNullArgs() {

		JWEJCAContext ctx = new JWEJCAContext(null, null, null, null, null);

		assertNull(ctx.getProvider());
		assertNull(ctx.getKeyEncryptionProvider());
		assertNull(ctx.getContentEncryptionProvider());
		assertNull(ctx.getMACProvider());
		assertNotNull(ctx.getSecureRandom());
	}


	public void testSettersAllNull() {

		JWEJCAContext ctx = new JWEJCAContext();

		ctx.setProvider(null);
		ctx.setKeyEncryptionProvider(null);
		ctx.setContentEncryptionProvider(null);
		ctx.setMACProvider(null);
		ctx.setSecureRandom(null);

		assertNull(ctx.getProvider());
		assertNull(ctx.getKeyEncryptionProvider());
		assertNull(ctx.getContentEncryptionProvider());
		assertNull(ctx.getMACProvider());
		assertNotNull(ctx.getSecureRandom());
	}


	public void testSetSecureRandom() {

		SecureRandom sr = new SecureRandom();

		JWEJCAContext ctx = new JWEJCAContext();
		ctx.setSecureRandom(sr);

		assertEquals(sr, ctx.getSecureRandom());
	}


	public void testSetGeneralAndSpecificProviders() {

		JWEJCAContext ctx = new JWEJCAContext();
		ctx.setProvider(new Provider("general", 1.0, "test") {
			});
		ctx.setKeyEncryptionProvider(new Provider("ke", 1.0, "test") { });
		ctx.setContentEncryptionProvider(new Provider("ce", 1.0, "test") { });
		ctx.setMACProvider(new Provider("mac", 1.0, "test") { });

		assertEquals("general", ctx.getProvider().getName());
		assertEquals("ke", ctx.getKeyEncryptionProvider().getName());
		assertEquals("ce", ctx.getContentEncryptionProvider().getName());
		assertEquals("mac", ctx.getMACProvider().getName());
	}


	public void testFallbackToGeneralProvider() {

		Provider provider = new Provider("general", 1.0, "test") { };

		JWEJCAContext ctx = new JWEJCAContext();
		ctx.setProvider(provider);

		assertEquals(provider, ctx.getProvider());
		assertEquals(provider, ctx.getKeyEncryptionProvider());
		assertEquals(provider, ctx.getContentEncryptionProvider());
		assertEquals(provider, ctx.getMACProvider());
	}
}
