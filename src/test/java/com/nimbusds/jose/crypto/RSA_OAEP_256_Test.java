/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import junit.framework.TestCase;


public class RSA_OAEP_256_Test extends TestCase {
	
	
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
				new JWEHeader(JWEAlgorithm.RSA_OAEP_256, enc),
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
				new JWEHeader(JWEAlgorithm.RSA_OAEP_256, enc),
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
	
	
	public void testRSAKeyTooShortToEncryptCEK()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		JWEObject jwe = new JWEObject(
				new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512),
				new Payload("Hello, world!"));
			
		try {
			jwe.encrypt(encrypter);
			fail();
		} catch (JOSEException e) {
			assertEquals("RSA block size exception: The RSA key is too short, try a longer one", e.getMessage());
			assertNotNull(e.getCause());
		}
	}
	
	
	
	/**
	 * RSA OAEP 256 JWE example from Brian Campbell (JOSE4J).
	 */
	public void testJOSE4JExample()
		throws Exception {
		
		String jwkString = "{\"kty\":\"RSA\",\"n\":\"2cQJH1f6yF9DcGa8Cmbnhn4LHLs5L6kNb2rxkrNFZArJLRaKvaC3tMCKZ8ZgIpO9bVMPx5UMjJoaf7p9O5BSApVqA2J10fUbdSIomCcDwvGo0eyhty0DILLWTMXzGEVM3BXzuJQoeDkuUCXXcCwA4Msyyd2OHVu-pB2OrGv6fcjHwjINty3UoKm08lCvAevBKHsuA-FFwQII9bycvRx5wRqFUjdMAyiOmLYBHBaJSi11g3HVexMcb29v14PSlVzdGUMN8oboa-zcIyaPrIiczLqAkSXQNdEFHrjsJHfFeNMfOblLM7icKN_tyWujYeItt4kqUIimPn5dHjwgcQYE7w\",\"e\":\"AQAB\",\"d\":\"dyUz3ItVceX1Tv1WqtZMnKA_0jN5gWMcL7ayf5JISAlCssGfnUre2C10TH0UQjbVMIh-nLMnD5KNJw9Qz5MR28oGG932Gq7hm__ZeA34l-OCe4DdpgwhpvVSHOU9MS1RdSUpmPavAcA_X6ikrAHXZSaoHhxzUgrNTpvBYQMfJUv_492fStIseQ9rwAMOpCWOiWMZOQm3KJVTLLunXdKf_UxmzmKXYKYZWke3AWIzUqnOfqIjfDTMunF4UWU0zKlhcsaQNmYMVrJGajD1bJdy_dbUU3LE8sx-bdkUI6oBk-sFtTTVyVdQcetG9kChJ5EnY5R6tt_4_xFG5kxzTo6qaQ\",\"p\":\"7yQmgE60SL7QrXpAJhChLgKnXWi6C8tVx1lA8FTpphpLaCtK-HbgBVHCprC2CfaM1mxFJZahxgFjC9ehuV8OzMNyFs8kekS82EsQGksi8HJPxyR1fU6ATa36ogPG0nNaqm3EDmYyjowhntgBz2OkbFAsTMHTdna-pZBRJa9lm5U\",\"q\":\"6R4dzo9LwHLO73EMQPQsmwXjVOvAS5W6rgQ-BCtMhec_QosAXIVE3AGyfweqZm6rurXCVFykDLwJ30GepLQ8nTlzeV6clx0x70saGGKKVmCsHuVYWwgIRyJTrt4SX29NQDZ_FE52NlO3OhPkj1ExSk_pGMqGRFd26K8g0jJsXXM\",\"dp\":\"VByn-hs0qB2Ncmb8ZycUOgWu7ljmjz1up1ZKU_3ZzJWVDkej7-6H7vcJ-u1OqgRxFv4v9_-aWPWl68VlWbkIkJbx6vniv6qrrXwBZu4klOPwEYBOXsucrzXRYOjpJp5yNl2zRslFYQQC00bwpAxNCdfNLRZDlXhAqCUxlYqyt10\",\"dq\":\"MJFbuGtWZvQEdRJicS3uFSY25LxxRc4eJJ8xpIC44rT5Ew4Otzf0zrlzzM92Cv1HvhCcOiNK8nRCwkbTnJEIh-EuU70IdttYSfilqSruk2x0r8Msk1qrDtbyBF60CToRKC2ycDKgolTyuaDnX4yU7lyTvdyD-L0YQwYpmmFy_k0\",\"qi\":\"vy7XCwZ3jyMGik81TIZDAOQKC8FVUc0TG5KVYfti4tgwzUqFwtuB8Oc1ctCKRbE7uZUPwZh4OsCTLqIvqBQda_kaxOxo5EF7iXj6yHmZ2s8P_Z_u3JLuh-oAT_6kmbLx6CAO0DbtKtxp24Ivc1hDfqSwWORgN1AOrSRCmE3nwxg\"}";
		
		RSAKey jwk = RSAKey.parse(jwkString);
		
		String jweString = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.fL5IL5cMCjjU9G9_ZjsD2XO0HIwTOwbVwulcZVw31_rx2qTcHzbYhIvrvbcVLTfJzn8xbQ3UEL442ZgZ1PcFYKENYePXiEyvYxPN8dmvj_OfLSJDEqR6kvwOb6nghGtxfzdB_VRvFt2eehbCA3gWpiOYHHvSTFdBPGx2KZHQisLz3oZR8EWiZ1woEpHy8a7FoQ2zzuDlZEJQOUrh09b_EJxmcE2jL6wmEtgabyxy3VgWg3GqSPUISlJZV9HThuVJezzktJdpntRDnAPUqjc8IwByGpMleIQcPuBUseRRPr_OsroOJ6eTl5DuFCmBOKb-eNNw5v-GEcVYr1w7X9oXoA.0frdIwx8P8UAzh1s9_PgOA.RAzILH0xfs0yxzML1CzzGExCfE2_wzWKs0FVuXfM8R5H68yTqTbqIqRCp2feAH5GSvluzmztk2_CkGNSjAyoaw.4nMUXOgmgWvM-08tIZ-h5w";
		
		JWEObject jweObject = JWEObject.parse(jweString);
		
		assertEquals(JWEAlgorithm.RSA_OAEP_256, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweObject.getHeader().getEncryptionMethod());
		
		RSADecrypter decrypter = new RSADecrypter(jwk.toRSAPrivateKey());
		
		// Get BouncyCastle for the test
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		jweObject.decrypt(decrypter);
		
		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
		
		assertEquals("Well, as of this moment, they're on DOUBLE SECRET PROBATION!", jweObject.getPayload().toString());
	}
}
