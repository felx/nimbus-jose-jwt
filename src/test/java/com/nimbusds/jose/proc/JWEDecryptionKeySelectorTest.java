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

package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import junit.framework.TestCase;
import org.junit.Assert;


public class JWEDecryptionKeySelectorTest extends TestCase {


	public void testWithDirectEncryption()
		throws Exception {

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		ImmutableSecret immutableSecret = new ImmutableSecret(secret);

		JWEDecryptionKeySelector keySelector = new JWEDecryptionKeySelector(JWEAlgorithm.DIR, EncryptionMethod.A128GCM, immutableSecret);
		assertEquals(JWEAlgorithm.DIR, keySelector.getExpectedJWEAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, keySelector.getExpectedJWEEncryptionMethod());

		JWKMatcher m = keySelector.createJWKMatcher(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM).build());
		assertTrue(m.matches(immutableSecret.getJWKSet().getKeys().get(0)));

		List<Key> matches = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM).build(), null);
		assertEquals(1, matches.size());
		Assert.assertArrayEquals(secret, matches.get(0).getEncoded());

	}
	

	public void testWithRSA_OAEP()
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.keyUse(KeyUse.ENCRYPTION)
			.build();

		keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.keyUse(KeyUse.ENCRYPTION)
			.build();

		JWEDecryptionKeySelector keySelector = new JWEDecryptionKeySelector(
			JWEAlgorithm.RSA_OAEP,
			EncryptionMethod.A128CBC_HS256,
			new ImmutableJWKSet(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2))));

		assertEquals(JWEAlgorithm.RSA_OAEP, keySelector.getExpectedJWEAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, keySelector.getExpectedJWEEncryptionMethod());

		// Test matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256)
			.keyID("1")
			.build());

		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("1"));
		assertTrue(m.getKeyUses().contains(KeyUse.ENCRYPTION));
		assertTrue(m.getAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256)
			.keyID("2")
			.build());

		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("2"));
		assertTrue(m.getKeyUses().contains(KeyUse.ENCRYPTION));
		assertTrue(m.getAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256)
			.keyID("1")
			.build());

		assertNull(m);

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM)
			.keyID("1")
			.build());

		assertNull(m);

		// Select for good header with key ID
		List<Key> candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).keyID("1").build(), null);
		Assert.assertArrayEquals(rsaJWK1.toRSAPrivateKey().getEncoded(), candidates.get(0).getEncoded());
		assertEquals(1, candidates.size());

		// Select for good header without key ID
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).build(), null);
		Assert.assertArrayEquals(rsaJWK1.toRSAPrivateKey().getEncoded(), candidates.get(0).getEncoded());
		Assert.assertArrayEquals(rsaJWK2.toRSAPrivateKey().getEncoded(), candidates.get(1).getEncoded());
		assertEquals(2, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).keyID("3").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWE alg
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWE enc
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());
	}
}
