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


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import junit.framework.TestCase;


/**
 * Tests RSA1-5 JWE encryption and decryption. Uses test RSA keys from the JWE
 * spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-04
 */
public class RSA1_5Test extends TestCase {


	private final static byte[] MOD = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121, 
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226, 
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61, 
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234, 
		(byte)226, (byte)219, (byte)118, (byte)206, (byte)118, (byte)  5, (byte)169, (byte)224, 

		(byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224, 
		(byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127, 
		(byte)121, (byte) 25, (byte)  4, (byte) 85, (byte)220, (byte)144, (byte)215, (byte)110, 
		(byte)130, (byte) 17, (byte) 68, (byte)228, (byte)129, (byte)138, (byte)  7, (byte)130, 
		(byte)231, (byte) 40, (byte)212, (byte)214, (byte) 17, (byte)179, (byte) 28, (byte)124,     

		(byte)151, (byte)178, (byte)207, (byte) 20, (byte) 14, (byte)154, (byte)222, (byte)113, 
		(byte)176, (byte) 24, (byte)198, (byte) 73, (byte)211, (byte)113, (byte)  9, (byte) 33, 
		(byte)178, (byte) 80, (byte) 13, (byte) 25, (byte) 21, (byte) 25, (byte)153, (byte)212, 
		(byte)206, (byte) 67, (byte)154, (byte)147, (byte) 70, (byte)194, (byte)192, (byte)183, 
		(byte)160, (byte) 83, (byte) 98, (byte)236, (byte)175, (byte) 85, (byte) 23, (byte) 97, 

		(byte) 75, (byte)199, (byte)177, (byte) 73, (byte)145, (byte) 50, (byte)253, (byte)206, 
		(byte) 32, (byte)179, (byte)254, (byte)236, (byte)190, (byte) 82, (byte) 73, (byte) 67, 
		(byte)129, (byte)253, (byte)252, (byte)220, (byte)108, (byte)136, (byte)138, (byte) 11, 
		(byte)192, (byte)  1, (byte) 36, (byte)239, (byte)228, (byte) 55, (byte) 81, (byte)113, 
		(byte) 17, (byte) 25, (byte)140, (byte) 63, (byte)239, (byte)146, (byte)  3, (byte)172,  

		(byte) 96, (byte) 60, (byte)227, (byte)233, (byte) 64, (byte)255, (byte)224, (byte)173, 
		(byte)225, (byte)228, (byte)229, (byte) 92, (byte)112, (byte) 72, (byte) 99, (byte) 97, 
		(byte) 26, (byte) 87, (byte)187, (byte)123, (byte) 46, (byte) 50, (byte) 90, (byte)202, 
		(byte)117, (byte) 73, (byte) 10, (byte)153, (byte) 47, (byte)224, (byte)178, (byte)163, 
		(byte) 77, (byte) 48, (byte) 46, (byte)154, (byte) 33, (byte)148, (byte) 34, (byte)228, 

		(byte) 33, (byte)172, (byte)216, (byte) 89, (byte) 46, (byte)225, (byte)127, (byte) 68, 
		(byte)146, (byte)234, (byte) 30, (byte)147, (byte) 54, (byte)146, (byte)  5, (byte)133, 
		(byte) 45, (byte) 78, (byte)254, (byte) 85, (byte) 55, (byte) 75, (byte)213, (byte) 86, 
		(byte)194, (byte)218, (byte)215, (byte)163, (byte)189, (byte)194, (byte) 54, (byte)  6, 
		(byte) 83, (byte) 36, (byte) 18, (byte)153, (byte) 53, (byte)  7, (byte) 48, (byte) 89, 

		(byte) 35, (byte) 66, (byte)144, (byte)  7, (byte) 65, (byte)154, (byte) 13, (byte) 97, 
		(byte) 75, (byte) 55, (byte)230, (byte)132, (byte)  3, (byte) 13, (byte)239, (byte) 71  };


	private static final byte[] EXP = { 1, 0, 1 };


	private static final byte[] MOD_PRIV = {
		(byte) 84, (byte) 80, (byte)150, (byte) 58, (byte)165, (byte)235, (byte)242, (byte)123, 
		(byte)217, (byte) 55, (byte) 38, (byte)154, (byte) 36, (byte)181, (byte)221, (byte)156, 
		(byte)211, (byte)215, (byte)100, (byte)164, (byte) 90, (byte) 88, (byte) 40, (byte)228, 
		(byte) 83, (byte)148, (byte) 54, (byte)122, (byte)  4, (byte) 16, (byte)165, (byte) 48, 
		(byte) 76, (byte)194, (byte) 26, (byte)107, (byte) 51, (byte) 53, (byte)179, (byte)165, 

		(byte) 31, (byte) 18, (byte)198, (byte)173, (byte) 78, (byte) 61, (byte) 56, (byte) 97, 
		(byte)252, (byte)158, (byte)140, (byte) 80, (byte) 63, (byte) 25, (byte)223, (byte)156, 
		(byte) 36, (byte)203, (byte)214, (byte)252, (byte)120, (byte) 67, (byte)180, (byte)167, 
		(byte)  3, (byte) 82, (byte)243, (byte) 25, (byte) 97, (byte)214, (byte) 83, (byte)133, 
		(byte) 69, (byte) 16, (byte)104, (byte) 54, (byte)160, (byte)200, (byte) 41, (byte) 83, 

		(byte)164, (byte)187, (byte) 70, (byte)153, (byte)111, (byte)234, (byte)242, (byte)158, 
		(byte)175, (byte) 28, (byte)198, (byte) 48, (byte)211, (byte) 45, (byte)148, (byte) 58, 
		(byte) 23, (byte) 62, (byte)227, (byte) 74, (byte) 52, (byte)117, (byte) 42, (byte) 90, 
		(byte) 41, (byte)249, (byte)130, (byte)154, (byte) 80, (byte)119, (byte) 61, (byte) 26, 
		(byte)193, (byte) 40, (byte)125, (byte) 10, (byte)152, (byte)174, (byte)227, (byte)225, 

		(byte)205, (byte) 32, (byte) 62, (byte) 66, (byte)  6, (byte)163, (byte)100, (byte) 99, 
		(byte)219, (byte) 19, (byte)253, (byte) 25, (byte)105, (byte) 80, (byte)201, (byte) 29, 
		(byte)252, (byte)157, (byte)237, (byte) 69, (byte)  1, (byte) 80, (byte)171, (byte)167, 
		(byte) 20, (byte)196, (byte)156, (byte)109, (byte)249, (byte) 88, (byte)  0, (byte)  3, 
		(byte)152, (byte) 38, (byte)165, (byte) 72, (byte) 87, (byte)  6, (byte)152, (byte) 71, 

		(byte)156, (byte)214, (byte) 16, (byte) 71, (byte) 30, (byte) 82, (byte) 51, (byte)103, 
		(byte) 76, (byte)218, (byte) 63, (byte)  9, (byte) 84, (byte)163, (byte)249, (byte) 91, 
		(byte)215, (byte) 44, (byte)238, (byte) 85, (byte)101, (byte)240, (byte)148, (byte)  1, 
		(byte) 82, (byte)224, (byte) 91, (byte)135, (byte)105, (byte)127, (byte) 84, (byte)171, 
		(byte)181, (byte)152, (byte)210, (byte)183, (byte)126, (byte) 24, (byte) 46, (byte)196, 

		(byte) 90, (byte)173, (byte) 38, (byte)245, (byte)219, (byte)186, (byte)222, (byte) 27, 
		(byte)240, (byte)212, (byte)194, (byte) 15, (byte) 66, (byte)135, (byte)226, (byte)178, 
		(byte)190, (byte) 52, (byte)245, (byte) 74, (byte) 65, (byte)224, (byte) 81, (byte)100, 
		(byte) 85, (byte) 25, (byte)204, (byte)165, (byte)203, (byte)187, (byte)175, (byte) 84, 
		(byte)100, (byte) 82, (byte) 15, (byte) 11, (byte) 23, (byte)202, (byte)151, (byte)107, 

		(byte) 54, (byte) 41, (byte)207, (byte)  3, (byte)136, (byte)229, (byte)134, (byte)131, 
		(byte) 93, (byte)139, (byte) 50, (byte)182, (byte)204, (byte) 93, (byte)130, (byte)89   };


	private static RSAPublicKey PUBLIC_KEY;


	private static PrivateKey PRIVATE_KEY;


	static {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, MOD), new BigInteger(1, EXP));
			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, MOD), new BigInteger(1, MOD_PRIV));

			PUBLIC_KEY = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			PRIVATE_KEY = keyFactory.generatePrivate(privateKeySpec);

		} catch (Exception e) {
			fail(e.getMessage());
		}
	}


	public void testClassAlgorithmSupport()
		throws Exception {

		assertEquals(3, RSAEncrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(RSAEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA1_5));
		assertTrue(RSAEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(RSAEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA_OAEP_256));

		assertEquals(3, RSADecrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(RSADecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA1_5));
		assertTrue(RSADecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(RSADecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.RSA_OAEP_256));
	}


	public void testClassEncryptionMethodSupport()
		throws Exception {

		assertEquals(8, RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		assertEquals(8, RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
	}


	public void testInstanceAlgorithmSupport()
		throws Exception {

		JWEEncrypter encrypter = new RSAEncrypter(PUBLIC_KEY);

		assertEquals(3, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA1_5));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA_OAEP_256));

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

		assertEquals(3, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA1_5));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.RSA_OAEP_256));
	}


	public void testInstanceEncryptionMethodSupport()
		throws Exception {

		JWEEncrypter encrypter = new RSAEncrypter(PUBLIC_KEY);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

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
	
	
	public void testRoundTripWithAllWithEncs()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		List<EncryptionMethod> encs = Arrays.asList(
			EncryptionMethod.A128CBC_HS256,
			EncryptionMethod.A192CBC_HS384,
			EncryptionMethod.A256CBC_HS512,
			EncryptionMethod.A128GCM,
			EncryptionMethod.A192GCM,
			EncryptionMethod.A256GCM,
			EncryptionMethod.A128CBC_HS256_DEPRECATED,
			EncryptionMethod.A256CBC_HS512_DEPRECATED);
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		
		for (EncryptionMethod enc: encs) {
			
			JWEObject jwe = new JWEObject(
				new JWEHeader(JWEAlgorithm.RSA1_5, enc),
				new Payload("Hello, world!"));
			
			assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
			
			jwe.encrypt(encrypter);
			
			assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
			
			String jweString = jwe.serialize();
			
			jwe = JWEObject.parse(jweString);
			
			jwe.decrypt(decrypter);
			
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			
			assertEquals("Hello, world!", jwe.getPayload().toString());
		}
	}
	
	
	public void testRoundTripWithAllWithEncs_withBouncyCastleProvider()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		List<EncryptionMethod> encs = Arrays.asList(
			EncryptionMethod.A128CBC_HS256,
			EncryptionMethod.A192CBC_HS384,
			EncryptionMethod.A256CBC_HS512,
			EncryptionMethod.A128GCM,
			EncryptionMethod.A192GCM,
			EncryptionMethod.A256GCM,
			EncryptionMethod.A128CBC_HS256_DEPRECATED,
			EncryptionMethod.A256CBC_HS512_DEPRECATED);
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		for (EncryptionMethod enc: encs) {
			
			JWEObject jwe = new JWEObject(
				new JWEHeader(JWEAlgorithm.RSA1_5, enc),
				new Payload("Hello, world!"));
			
			assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
			
			jwe.encrypt(encrypter);
			
			assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
			
			String jweString = jwe.serialize();
			
			jwe = JWEObject.parse(jweString);
			
			jwe.decrypt(decrypter);
			
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			
			assertEquals("Hello, world!", jwe.getPayload().toString());
		}
	}


	public void testRSAJWKConstructors()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM);

		JWEObject jweObject = new JWEObject(header, new Payload("I think therefore I am."));

		RSAKey rsaJWK = new RSAKey.Builder(PUBLIC_KEY).privateKey((RSAPrivateKey) PRIVATE_KEY).build();

		RSAEncrypter encrypter = new RSAEncrypter(rsaJWK);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		assertEquals(PUBLIC_KEY, encrypter.getPublicKey());

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		RSADecrypter decrypter = new RSADecrypter(rsaJWK);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		assertEquals(PRIVATE_KEY, decrypter.getPrivateKey());

		jweObject.decrypt(decrypter);

		assertEquals("I think therefore I am.", jweObject.getPayload().toString());
	}


	public void testRFCExampleDecrypt()
		throws Exception {

		// From JWE spec http://tools.ietf.org/html/rfc7516#appendix-A.2

		String jweString = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
			"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" +
			"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" +
			"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" +
			"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" +
			"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" +
			"-B3oWh2TbqmScqXMR4gp_A." +
			"AxY8DCtDaGlsbGljb3RoZQ." +
			"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
			"9hH0vgRfYgPnAHOd8stkvw";

		JWEObject jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		Payload payload = jweObject.getPayload();

		assertEquals("Live long and prosper.", payload.toString());
	}


	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new RSAEncrypter(PUBLIC_KEY);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCookbookExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.1

		String json="{"+
			"\"kty\":\"RSA\","+
			"\"kid\":\"frodo.baggins@hobbiton.example\","+
			"\"use\":\"enc\","+
			"\"n\":\"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT"+
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx"+
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U"+
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c"+
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy"+
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA"+
			"VotGlvMQ\","+
			"\"e\":\"AQAB\","+
			"\"d\":\"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy"+
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO"+
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6"+
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP"+
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN"+
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v"+
			"pzj85bQQ\","+
			"\"p\":\"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE"+
			"oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH"+
			"7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ"+
			"2VFmU\","+
			"\"q\":\"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V"+
			"F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb"+
			"9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8"+
			"d6Et0\","+
			"\"dp\":\"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH"+
			"QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV"+
			"RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf"+
			"lo0rYU\","+
			"\"dq\":\"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb"+
			"pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A"+
			"CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14"+
			"TkXlHE\","+
			"\"qi\":\"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ"+
			"lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7"+
			"Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx"+
			"2bQ_mM\""+
			"}";

		RSAKey jwk = RSAKey.parse(json);


		String jwe = "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm"+
			"V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"+
			"."+
			"laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF"+
			"vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G"+
			"Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG"+
			"TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl"+
			"zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh"+
			"MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw"+
			"."+
			"bbd5sTkYwhAIqfHsx8DayA"+
			"."+
			"0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r"+
			"aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O"+
			"WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV"+
			"yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0"+
			"zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2"+
			"O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW"+
			"i7lzA6BP430m"+
			"."+
			"kvKuFBXHe5mQr4lqgobAUg";

		JWEObject jweObject = JWEObject.parse(jwe);

		assertEquals(JWEAlgorithm.RSA1_5, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweObject.getHeader().getEncryptionMethod());
		assertEquals("frodo.baggins@hobbiton.example", jweObject.getHeader().getKeyID());

		JWEDecrypter decrypter = new RSADecrypter(jwk.toRSAPrivateKey());

		jweObject.decrypt(decrypter);

		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			customParam("EXP", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("EXP"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new RSAEncrypter(PUBLIC_KEY);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY, new HashSet<>(Collections.singletonList("EXP")));

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			customParam("EXP", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("EXP"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new RSAEncrypter(PUBLIC_KEY);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}


	public void testExampleDecryptDeprecatedA128CBC_HS256()
		throws Exception {

		// From JWE spec draft-ietf-jose-json-web-encryption-08#appendix-A.2

		String jweString =
			"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0." +
			"ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1I" +
			"W40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkI" +
			"nMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU1" +
			"2Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_ad" +
			"x8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq" +
			"_vPE4-Gtev4N4K4Eudlj4Q." +
			"AxY8DCtDaGlsbGljb3RoZQ." +
			"Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ." +
			"8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk";

		JWEObject jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new RSADecrypter(PRIVATE_KEY);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		Payload payload = jweObject.getPayload();

		assertEquals("No matter where you go, there you are.", payload.toString());
	}


	public void testRejectPrivateKeyWithNonRSAAlg() {

		try {
			new RSADecrypter(new PrivateKey() {
				@Override
				public String getAlgorithm() {
					return "some-alg";
				}


				@Override
				public String getFormat() {
					return null;
				}


				@Override
				public byte[] getEncoded() {
					return new byte[0];
				}
			});
		} catch (IllegalArgumentException e) {
			assertEquals("The private key algorithm must be RSA", e.getMessage());
		}
	}
	
	
	public void testNoCEKExceptionReportingOnBadPublicKey()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		
		// Good pair
		RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();
		
		// Bad public key
		RSAPublicKey badPublicKey = (RSAPublicKey) gen.generateKeyPair().getPublic();
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM),
			new Payload("Hello, world!"));
		
		jweObject.encrypt(new RSAEncrypter(badPublicKey));
		
		String jwe = jweObject.serialize();
		
		jweObject = JWEObject.parse(jwe);
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		
		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			assertEquals("AES/GCM/NoPadding decryption failed: Tag mismatch!", e.getMessage());
			assertNull(decrypter.getCEKDecryptionException());
		}
	}
	
	
	public void testNoCEKExceptionReportingOnBadPrivateKey()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		
		// Good pair
		RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();
		
		// Bad private key
		PrivateKey badPrivateKey = gen.generateKeyPair().getPrivate();
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM),
			new Payload("Hello, world!"));
		
		jweObject.encrypt(new RSAEncrypter(publicKey));
		
		String jwe = jweObject.serialize();
		
		jweObject = JWEObject.parse(jwe);
		
		RSADecrypter decrypter = new RSADecrypter(badPrivateKey);
		
		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			assertEquals("AES/GCM/NoPadding decryption failed: Tag mismatch!", e.getMessage());
			assertNull(decrypter.getCEKDecryptionException());
		}
	}
	
	
	public void testRSAKeyTooShortToEncryptCEK()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(512);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		JWEObject jwe = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256CBC_HS512),
			new Payload("Hello, world!"));
		
		try {
			jwe.encrypt(encrypter);
			fail();
		} catch (JOSEException e) {
			assertEquals("RSA block size exception: The RSA key is too short, try a longer one", e.getMessage());
			assertNotNull(e.getCause());
		}
	}
}