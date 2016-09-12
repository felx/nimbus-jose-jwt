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


import java.nio.charset.Charset;
import java.util.Arrays;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;


/**
 * Password-based encryption test.
 */
public class PBES2Test extends TestCase {


	public void testClassAlgorithmSupport() {

		assertEquals(3, PasswordBasedEncrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS512_A256KW));

		assertEquals(3, PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.PBES2_HS512_A256KW));
	}


	public void testClassEncryptionMethodSupport()
		throws Exception {

		assertEquals(8, PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		assertEquals(8, PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
	}


	public void testInstanceAlgorithmSupport() {

		JWEEncrypter encrypter = new PasswordBasedEncrypter("secret", 8, 1000);

		assertEquals(3, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS512_A256KW));

		JWEDecrypter decrypter = new PasswordBasedDecrypter("secret");

		assertEquals(3, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS512_A256KW));
	}


	public void testInstanceEncryptionMethodSupport()
		throws Exception {

		JWEEncrypter encrypter = new PasswordBasedEncrypter("secret", 8, 1000);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new PasswordBasedDecrypter("secret");

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


	public void testConfigConstants() {

		assertEquals(8, PasswordBasedEncrypter.MIN_SALT_LENGTH);
		assertEquals(1000, PasswordBasedEncrypter.MIN_RECOMMENDED_ITERATION_COUNT);
	}


	public void testPasswordByteConstructors() {

		byte[] password = "secret".getBytes(Charset.forName("UTF-8"));

		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password, 8, 1000);

		assertTrue(Arrays.equals(password, encrypter.getPassword()));
		assertEquals("secret", encrypter.getPasswordString());

		assertEquals(8, encrypter.getSaltLength());
		assertEquals(1000, encrypter.getIterationCount());

		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password);

		assertTrue(Arrays.equals(password, decrypter.getPassword()));
		assertEquals("secret", decrypter.getPasswordString());
	}


	public void testPBES2_HS256_A128KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128GCM).build(), new Payload(plaintext));

		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password, 16, 8192);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		jweObject = JWEObject.parse(jweObject.serialize());

		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals(plaintext, jweObject.getPayload().toString());
	}


	public void testPBES2_HS384_A192KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS384_A192KW, EncryptionMethod.A128CBC_HS256).build(), new Payload(plaintext));

		jweObject.encrypt(new PasswordBasedEncrypter(password, 16, 8192));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		assertEquals(plaintext, jweObject.getPayload().toString());
	}


	public void testPBES2_HS512_A256KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS512_A256KW, EncryptionMethod.A256CBC_HS512).build(), new Payload(plaintext));

		jweObject.encrypt(new PasswordBasedEncrypter(password, 16, 8192));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		assertEquals(plaintext, jweObject.getPayload().toString());
	}


	// See http://tools.ietf.org/html/rfc7520#section-5.3.1
	public void testDecryptCookbookExample()
		throws Exception {

		String jwe = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3" +
			"hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl" +
			"bmMiOiJBMTI4Q0JDLUhTMjU2In0" +
			"." +
			"d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g" +
			"." +
			"VBiCzVHNoLiR3F4V82uoTQ" +
			"." +
			"23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR" +
			"sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l" +
			"TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb" +
			"6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL" +
			"_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd" +
			"PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok" +
			"AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-" +
			"zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V" +
			"3kobXZ77ulMwDs4p" +
			"." +
			"0HlwodAhOCILG5SQ2LQ9dg";

		final String password = "entrap_o\u2013peter_long\u2013credit_tun";

		JWEObject jweObject = JWEObject.parse(jwe);

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		String expectedPlainText = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\",\"use\":\"enc\",\"alg\":\"A128GCM\",\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\"},{\"kty\":\"oct\",\"kid\":\"81b20965-8332-43d9-a468-82160ad91ac8\",\"use\":\"enc\",\"alg\":\"A128KW\",\"k\":\"GZy6sIZ6wl9NJOKB-jnmVQ\"},{\"kty\":\"oct\",\"kid\":\"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d\",\"use\":\"enc\",\"alg\":\"A256GCMKW\",\"k\":\"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8\"}]}";

		assertEquals(expectedPlainText, jweObject.getPayload().toString());
	}
}
