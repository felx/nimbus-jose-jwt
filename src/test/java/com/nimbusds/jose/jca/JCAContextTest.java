package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the simple JCA context.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-02)
 */
public class JCAContextTest extends TestCase {


	public void testDefaultConstructor() {

		JCAContext context = new JCAContext();
		assertNull(context.getProvider());
		assertNotNull(context.getSecureRandom());
	}


	public void testConstructor() {

		Provider provider = new Provider("general", 1.0, "test") {};
		SecureRandom sr = new SecureRandom();

		JCAContext context = new JCAContext(provider, sr);

		assertEquals(provider, context.getProvider());
		assertEquals(sr, context.getSecureRandom());
	}


	public void testSetters() {

		JCAContext context = new JCAContext();

		context = context.withProvider(new Provider("general", 1.0, "test") {});
		assertEquals("general", context.getProvider().getName());

		SecureRandom sr = new SecureRandom();
		context = context.withSecureRandom(sr);
		assertEquals(sr, context.getSecureRandom());
	}
}
