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

package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.HashSet;

import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.junit.Assert;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;


/**
 * Tests A128GCMKW JWE encryption and decryption. 
 *
 * @author Melisa Halsband 
 * @version 2015-09-18
 */
public class A128GCMKWTest extends TestCase {


	// 128-bit shared symmetric key
	private final static byte[] key128 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226 };


	public void testKeyLength() {

		assertEquals(128, key128.length * 8);
	}


	public void testInstanceAlgorithmSupport()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key128);

		assertEquals(2, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128GCMKW));

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(2, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128GCMKW));
	}


	public void testInstanceEncryptionMethodSupport()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key128);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(8, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
	}


	public void testWithA128CBC_HS256()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}

	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}

	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		AESDecrypter decrypter = new AESDecrypter(new SecretKeySpec(key128, "AES"), new HashSet<>(Collections.singletonList("exp")));
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key128);

		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}


	public void testWithDeprecatedA128CBC_HS256()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithDeprecatedA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}
}
