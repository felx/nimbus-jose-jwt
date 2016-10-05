/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

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
