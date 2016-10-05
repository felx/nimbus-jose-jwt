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
import com.nimbusds.jose.jwk.OctetSequenceKey;


/**
 * Tests A256GCMKW JWE encryption and decryption.
 *
 * @author Melisa Halsband
 * @version 2015-09-18
 */
public class A256GCMKWTest extends TestCase {


	// 256-bit shared symmetric key
	private final static byte[] key256 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61,
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234 };


	public void testKeyLength() {

		assertEquals(256, key256.length * 8);
	}


	public void testInstanceAlgorithmSupport()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key256);

		assertEquals(2, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256GCMKW));

		JWEDecrypter decrypter = new AESDecrypter(key256);

		assertEquals(2, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256GCMKW));
	}


	public void testInstanceEncryptionMethodSupport()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key256);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new AESDecrypter(key256);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key256, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}


	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		AESDecrypter decrypter = new AESDecrypter(new SecretKeySpec(key256, "AES"), new HashSet<>(Collections.singletonList("exp")));
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key256);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128CBC_HS256_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithDeprecatedA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key256);
		encrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key256);
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	// http://tools.ietf.org/html/rfc7520#section-5.7.5
	public void testDecryptCookbookExample()
		throws Exception {

		String jweString =
			"eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj" +
			"IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3" +
			"IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni" +
			"J9" +
			"." +
			"lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok" +
			"." +
			"gz6NjyEFNm_vm8Gj6FwoFQ" +
			"." +
			"Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaE" +
			"eVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCz" +
			"LjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFq" +
			"hpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hde" +
			"b6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0Jtj" +
			"xAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR" +
			"1B-gxpNk3xWU" +
			"." +
			"DKW7jrb4WaRSNfbXVPlT5g";

		JWEObject jweObject = JWEObject.parse(jweString);

		assertEquals(JWEAlgorithm.A256GCMKW, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweObject.getHeader().getEncryptionMethod());


		String jwkString = "{" +
			"\"kty\": \"oct\"," +
			"\"kid\": \"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d\"," +
			"\"use\": \"enc\"," +
			"\"alg\": \"A256GCMKW\"," +
			"\"k\": \"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8\"" +
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(jwkString);

		AESDecrypter decrypter = new AESDecrypter(jwk.getKeyValue().decode());
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		String message = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

		assertEquals(message, jweObject.getPayload().toString());
	}
}

