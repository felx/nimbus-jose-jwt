package com.nimbusds.jose.jwk.source;


import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.junit.Assert;


public class ImmutableSecretTest extends TestCase {
	

	public void testByteArrayConstructor() {

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		ImmutableSecret immutableSecret = new ImmutableSecret(secret);
		Assert.assertArrayEquals(secret, immutableSecret.getSecret());
		Assert.assertArrayEquals(secret, immutableSecret.getSecretKey().getEncoded());
		assertEquals(1, immutableSecret.getJWKSet().getKeys().size());
	}


	public void testSecretKeyConstructor() {

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		SecretKey secretKey = new SecretKeySpec(secret, "AES");
		ImmutableSecret immutableSecret = new ImmutableSecret(secretKey);
		Assert.assertArrayEquals(secret, immutableSecret.getSecret());
		Assert.assertArrayEquals(secret, immutableSecret.getSecretKey().getEncoded());
		assertEquals(1, immutableSecret.getJWKSet().getKeys().size());
	}
}
