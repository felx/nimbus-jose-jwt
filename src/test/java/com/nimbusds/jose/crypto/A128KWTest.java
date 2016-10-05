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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * Tests A128KW JWE encryption and decryption.
 *
 * @author Melisa Halsband
 * @version 2015-09-18
 */
public class A128KWTest extends TestCase {


	// 128-bit shared symmetric key
	private final static byte[] key128 = {
		(byte) 177, (byte) 119, (byte) 33,  (byte) 13,  (byte) 164, (byte) 30,  (byte) 108, (byte) 121,
		(byte) 207, (byte) 136, (byte) 107, (byte) 242, (byte) 12,  (byte) 224, (byte) 19,  (byte) 226};


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

		AESDecrypter decrypter = new AESDecrypter(key128);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter) encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}


	public void testJWKConstructor()
		throws Exception {

		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM),
			new Payload("I think therefore I am."));

		OctetSequenceKey oct = new OctetSequenceKey.Builder(key128).build();

		AESEncrypter encrypter = new AESEncrypter(oct);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, encrypter.getKey().getEncoded());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		AESDecrypter decrypter = new AESDecrypter(oct);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		Assert.assertArrayEquals(key128, decrypter.getKey().getEncoded());

		jweObject.decrypt(decrypter);
		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		assertEquals("I think therefore I am.", jweObject.getPayload().toString());
	}


	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		AESDecrypter decrypter = new AESDecrypter(new SecretKeySpec(key128, "AES"), new HashSet<>(Collections.singletonList("exp")));

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		AESDecrypter decrypter = new AESDecrypter(key128);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithDeprecatedA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		AESDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}



	// http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-4.8
	public void testDecryptCookbookExample()
		throws Exception {

		String jweString = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC" +
			"04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0" +
			"." +
			"CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx" +
			"." +
			"Qx0pmsDa8KnJc9Jo" +
			"." +
			"AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6" +
			"1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe" +
			"F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE" +
			"wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p" +
			"uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa" +
			"a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF" +
			"." +
			"ER7MWJZ1FBI_NKvn7Zb1Lw";

		JWEObject jweObject = JWEObject.parse(jweString);

		assertEquals(JWEAlgorithm.A128KW, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, jweObject.getHeader().getEncryptionMethod());


		String jwkString = "{" +
			"\"kty\": \"oct\"," +
			"\"kid\": \"81b20965-8332-43d9-a468-82160ad91ac8\"," +
			"\"use\": \"enc\"," +
			"\"alg\": \"A128KW\"," +
			"\"k\": \"GZy6sIZ6wl9NJOKB-jnmVQ\"" +
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(jwkString);

		AESDecrypter decrypter = new AESDecrypter(jwk.getKeyValue().decode());
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		String message = "You can trust us to stick with you through thick and thin\u2013to the bitter end. And you can trust us to keep any secret of yours\u2013closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

		assertEquals(message, jweObject.getPayload().toString());
	}


	public void testWithNestedSignedJWT()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		signedJWT.sign(new MACSigner("12345678901234567890123456789012"));

		assertEquals(JWSObject.State.SIGNED, signedJWT.getState());

		Payload payload = new Payload(signedJWT);
		assertEquals(Payload.Origin.SIGNED_JWT, payload.getOrigin());
		assertEquals(signedJWT, payload.toSignedJWT());
		assertEquals(signedJWT, payload.toJWSObject());

		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM), payload);

		AESEncrypter encrypter = new AESEncrypter(key128);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals(JWEObject.State.ENCRYPTED, jweObject.getState());

		String compactEncoding = jweObject.serialize();

		AESDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject = JWEObject.parse(compactEncoding);
		assertEquals(compactEncoding, jweObject.getParsedString());

		jweObject.decrypt(decrypter);

		payload = jweObject.getPayload();

		signedJWT = payload.toSignedJWT();

		assertTrue(signedJWT.verify(new MACVerifier("12345678901234567890123456789012")));

		assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
	}

}