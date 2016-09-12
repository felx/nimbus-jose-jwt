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
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;


/**
 * Tests the content encryption / decryption provider.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class ContentCryptoProviderTest extends TestCase {


	public void testCompatibleEncryptionMethods() {

		// 128 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128).contains(EncryptionMethod.A128GCM));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128).size());

		// 192 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192).contains(EncryptionMethod.A192GCM));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192).size());

		// 256 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A256GCM));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertEquals(3, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).size());

		// 384 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384).contains(EncryptionMethod.A192CBC_HS384));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384).size());

		// 512 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertEquals(2, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).size());

		// Total
		assertEquals(5, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.size());
	}


	public void test_A256CBC_HS512()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[64];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAContext jcaProvider = new JWEJCAContext();
		jcaProvider.setProvider(BouncyCastleProviderSingleton.getInstance());

		JWECryptoParts jweParts = ContentCryptoProvider.encrypt(
			header,
			clearText,
			cek,
			encryptedKey,
			jcaProvider);

		assertTrue(Arrays.equals(clearText, ContentCryptoProvider.decrypt(
			header,
			encryptedKey,
			jweParts.getInitializationVector(),
			jweParts.getCipherText(),
			jweParts.getAuthenticationTag(),
			cek,
			jcaProvider)));
	}

	public void test_A256CBC_HS512_cekTooShort()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[32];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAContext jcaProvider = new JWEJCAContext();
		jcaProvider.setProvider(BouncyCastleProviderSingleton.getInstance());

		try {
			ContentCryptoProvider.encrypt(
				header,
				clearText,
				cek,
				encryptedKey,
				jcaProvider);

			fail();

		} catch (KeyLengthException e) {

			assertEquals("The Content Encryption Key (CEK) length for A256CBC-HS512 must be 512 bits", e.getMessage());
		}
	}


	public void test_A256GCM_cekTooShort()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[16];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAContext jcaProvider = new JWEJCAContext();
		jcaProvider.setProvider(BouncyCastleProviderSingleton.getInstance());

		try {
			ContentCryptoProvider.encrypt(
				header,
				clearText,
				cek,
				encryptedKey,
				jcaProvider);

			fail();

		} catch (KeyLengthException e) {

			assertEquals("The Content Encryption Key (CEK) length for A256GCM must be 256 bits", e.getMessage());
		}
	}


	public void testKeyGen()
		throws Exception {

		SecureRandom randomGen = new SecureRandom();

		assertEquals(ByteUtils.byteLength(128), ContentCryptoProvider.generateCEK(EncryptionMethod.A128GCM, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(192), ContentCryptoProvider.generateCEK(EncryptionMethod.A192GCM, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(256), ContentCryptoProvider.generateCEK(EncryptionMethod.A256GCM, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(256), ContentCryptoProvider.generateCEK(EncryptionMethod.A128CBC_HS256, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(384), ContentCryptoProvider.generateCEK(EncryptionMethod.A192CBC_HS384, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(512), ContentCryptoProvider.generateCEK(EncryptionMethod.A256CBC_HS512, randomGen).getEncoded().length);

		assertEquals(ByteUtils.byteLength(256), ContentCryptoProvider.generateCEK(EncryptionMethod.A128CBC_HS256_DEPRECATED, randomGen).getEncoded().length);
		assertEquals(ByteUtils.byteLength(512), ContentCryptoProvider.generateCEK(EncryptionMethod.A256CBC_HS512_DEPRECATED, randomGen).getEncoded().length);
	}
}
