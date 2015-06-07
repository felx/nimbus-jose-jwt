package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the JWE JCA context.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-07)
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
	
	
	public void testGeneralProviderConstructor() {
		
		JWEJCAContext ctx = new JWEJCAContext(new Provider("general", 1.0, "test") {});
		
		assertEquals("general", ctx.getProvider().getName());
		assertEquals("general", ctx.getKeyEncryptionProvider().getName());
		assertEquals("general", ctx.getContentEncryptionProvider().getName());
		assertEquals("general", ctx.getMACProvider().getName());
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

		ctx = ctx.withProvider(null);
		ctx = ctx.withKeyEncryptionProvider(null);
		ctx = ctx.withContentEncryptionProvider(null);
		ctx = ctx.withMACProvider(null);
		ctx = ctx.withSecureRandom(null);

		assertNull(ctx.getProvider());
		assertNull(ctx.getKeyEncryptionProvider());
		assertNull(ctx.getContentEncryptionProvider());
		assertNull(ctx.getMACProvider());
		assertNotNull(ctx.getSecureRandom());
	}


	public void testSetSecureRandom() {

		SecureRandom sr = new SecureRandom();

		JWEJCAContext ctx = new JWEJCAContext().withSecureRandom(sr);

		assertEquals(sr, ctx.getSecureRandom());
	}


	public void testSetGeneralAndSpecificProviders() {

		JWEJCAContext ctx = new JWEJCAContext().
			withProvider(new Provider("general", 1.0, "test") {
			}).
			withKeyEncryptionProvider(new Provider("ke", 1.0, "test") { }).
			withContentEncryptionProvider(new Provider("ce", 1.0, "test") { }).
			withMACProvider(new Provider("mac", 1.0, "test") { });

		assertEquals("general", ctx.getProvider().getName());
		assertEquals("ke", ctx.getKeyEncryptionProvider().getName());
		assertEquals("ce", ctx.getContentEncryptionProvider().getName());
		assertEquals("mac", ctx.getMACProvider().getName());
	}


	public void testFallbackToGeneralProvider() {

		Provider provider = new Provider("general", 1.0, "test") { };

		JWEJCAContext ctx = new JWEJCAContext().withProvider(provider);

		assertEquals(provider, ctx.getProvider());
		assertEquals(provider, ctx.getKeyEncryptionProvider());
		assertEquals(provider, ctx.getContentEncryptionProvider());
		assertEquals(provider, ctx.getMACProvider());
	}
}
