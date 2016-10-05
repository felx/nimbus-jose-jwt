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

package com.nimbusds.jose.crypto.factories;


import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.proc.JWEDecrypterFactory;
import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests the default JWE decrypter factory.
 */
public class DefaultJWEDecrypterFactoryTest extends TestCase {
	

	public void testInterfaces() {

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		assertTrue(factory instanceof JWEDecrypterFactory);
		assertTrue(factory instanceof JCAAware);
		assertTrue(factory instanceof JWEProvider);
	}


	public void testAlgSupport() {

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		assertTrue(factory.supportedJWEAlgorithms().containsAll(JWEAlgorithm.Family.RSA));
		assertTrue(factory.supportedJWEAlgorithms().containsAll(JWEAlgorithm.Family.ECDH_ES));
		assertTrue(factory.supportedJWEAlgorithms().containsAll(JWEAlgorithm.Family.AES_GCM_KW));
		assertTrue(factory.supportedJWEAlgorithms().containsAll(JWEAlgorithm.Family.AES_KW));
		assertTrue(factory.supportedJWEAlgorithms().containsAll(JWEAlgorithm.Family.PBES2));
		assertTrue(factory.supportedJWEAlgorithms().contains(JWEAlgorithm.DIR));

		assertEquals(17, factory.supportedJWEAlgorithms().size());
	}


	public void testEncSupport() {

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		assertTrue(factory.supportedEncryptionMethods().containsAll(EncryptionMethod.Family.AES_GCM));
		assertTrue(factory.supportedEncryptionMethods().containsAll(EncryptionMethod.Family.AES_CBC_HMAC_SHA));
		assertTrue(factory.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(factory.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		assertEquals(8, factory.supportedEncryptionMethods().size());
	}


	public void testDefaultJCAContext() {

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		assertNotNull(factory.getJCAContext().getSecureRandom());
		assertNull(factory.getJCAContext().getProvider());
		assertNull(factory.getJCAContext().getKeyEncryptionProvider());
		assertNull(factory.getJCAContext().getMACProvider());
		assertNull(factory.getJCAContext().getContentEncryptionProvider());
	}





	public void testSetSecureRandom()
		throws Exception {

		SecureRandom secureRandom = new SecureRandom() {
			@Override
			public String getAlgorithm() {
				return "test";
			}
		};

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
		factory.getJCAContext().setSecureRandom(secureRandom);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		SecretKey key = keyGen.generateKey();
		assertEquals(128, ByteUtils.bitLength(key.getEncoded()));

		JWEDecrypter decrypter = factory.createJWEDecrypter(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), key);

		assertEquals("test", decrypter.getJCAContext().getSecureRandom().getAlgorithm());
	}


	public void testSetProvider()
		throws Exception {

		DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
		factory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		factory.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		factory.getJCAContext().setMACProvider(BouncyCastleProviderSingleton.getInstance());
		factory.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		SecretKey key = keyGen.generateKey();
		assertEquals(128, ByteUtils.bitLength(key.getEncoded()));

		JWEDecrypter decrypter = factory.createJWEDecrypter(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), key);

		assertEquals("BC", decrypter.getJCAContext().getProvider().getName());
		assertEquals("BC", decrypter.getJCAContext().getKeyEncryptionProvider().getName());
		assertEquals("BC", decrypter.getJCAContext().getMACProvider().getName());
		assertEquals("BC", decrypter.getJCAContext().getContentEncryptionProvider().getName());
	}
}
