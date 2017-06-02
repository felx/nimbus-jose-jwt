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


import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;
import org.junit.Assert;


/**
 * Tests the authenticated AES/CBC encryption and decryption methods. Uses test 
 * vectors from draft-ietf-jose-json-web-algorithms-10, appendix C.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-06-01
 */
public class AESCBCTest extends TestCase {


	private static final byte[] INPUT_KEY_256 = 
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f  };


	private static final byte[] INPUT_KEY_512 =
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
		  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
		  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
		  (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27, 
		  (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b, (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f,
		  (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, 
		  (byte)0x38, (byte)0x39, (byte)0x3a, (byte)0x3b, (byte)0x3c, (byte)0x3d, (byte)0x3e, (byte)0x3f  };


	private static final byte[] PLAIN_TEXT =
		{ (byte)0x41, (byte)0x20, (byte)0x63, (byte)0x69, (byte)0x70, (byte)0x68, (byte)0x65, (byte)0x72, 
	          (byte)0x20, (byte)0x73, (byte)0x79, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x6d, (byte)0x20,
	          (byte)0x6d, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x74, 
	          (byte)0x20, (byte)0x62, (byte)0x65, (byte)0x20, (byte)0x72, (byte)0x65, (byte)0x71, (byte)0x75,
		  (byte)0x69, (byte)0x72, (byte)0x65, (byte)0x64, (byte)0x20, (byte)0x74, (byte)0x6f, (byte)0x20, 
		  (byte)0x62, (byte)0x65, (byte)0x20, (byte)0x73, (byte)0x65, (byte)0x63, (byte)0x72, (byte)0x65,
		  (byte)0x74, (byte)0x2c, (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64, (byte)0x20, (byte)0x69, 
		  (byte)0x74, (byte)0x20, (byte)0x6d, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x62,
		  (byte)0x65, (byte)0x20, (byte)0x61, (byte)0x62, (byte)0x6c, (byte)0x65, (byte)0x20, (byte)0x74, 
		  (byte)0x6f, (byte)0x20, (byte)0x66, (byte)0x61, (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x69,
		  (byte)0x6e, (byte)0x74, (byte)0x6f, (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x20, 
		  (byte)0x68, (byte)0x61, (byte)0x6e, (byte)0x64, (byte)0x73, (byte)0x20, (byte)0x6f, (byte)0x66,
		  (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x65, (byte)0x6e, (byte)0x65, 
		  (byte)0x6d, (byte)0x79, (byte)0x20, (byte)0x77, (byte)0x69, (byte)0x74, (byte)0x68, (byte)0x6f,
		  (byte)0x75, (byte)0x74, (byte)0x20, (byte)0x69, (byte)0x6e, (byte)0x63, (byte)0x6f, (byte)0x6e, 
		  (byte)0x76, (byte)0x65, (byte)0x6e, (byte)0x69, (byte)0x65, (byte)0x6e, (byte)0x63, (byte)0x65 };


	private static final byte[] IV =
		{ (byte)0x1a, (byte)0xf3, (byte)0x8c, (byte)0x2d, (byte)0xc2, (byte)0xb9, (byte)0x6f, (byte)0xfd, 
		  (byte)0xd8, (byte)0x66, (byte)0x94, (byte)0x09, (byte)0x23, (byte)0x41, (byte)0xbc, (byte)0x04 };


	private static final byte[] AAD =
		{ (byte)0x54, (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x73, (byte)0x65, (byte)0x63, (byte)0x6f, 
		  (byte)0x6e, (byte)0x64, (byte)0x20, (byte)0x70, (byte)0x72, (byte)0x69, (byte)0x6e, (byte)0x63,
		  (byte)0x69, (byte)0x70, (byte)0x6c, (byte)0x65, (byte)0x20, (byte)0x6f, (byte)0x66, (byte)0x20, 
		  (byte)0x41, (byte)0x75, (byte)0x67, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x20,
		  (byte)0x4b, (byte)0x65, (byte)0x72, (byte)0x63, (byte)0x6b, (byte)0x68, (byte)0x6f, (byte)0x66, 
		  (byte)0x66, (byte)0x73 };


	private static final byte[] AAD_LENGTH = 
		{ (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x50 };


	private static final byte[] CIPHER_TEXT_256 = 
		{ (byte)0xc8, (byte)0x0e, (byte)0xdf, (byte)0xa3, (byte)0x2d, (byte)0xdf, (byte)0x39, (byte)0xd5, 
		  (byte)0xef, (byte)0x00, (byte)0xc0, (byte)0xb4, (byte)0x68, (byte)0x83, (byte)0x42, (byte)0x79,
		  (byte)0xa2, (byte)0xe4, (byte)0x6a, (byte)0x1b, (byte)0x80, (byte)0x49, (byte)0xf7, (byte)0x92, 
		  (byte)0xf7, (byte)0x6b, (byte)0xfe, (byte)0x54, (byte)0xb9, (byte)0x03, (byte)0xa9, (byte)0xc9,
		  (byte)0xa9, (byte)0x4a, (byte)0xc9, (byte)0xb4, (byte)0x7a, (byte)0xd2, (byte)0x65, (byte)0x5c, 
		  (byte)0x5f, (byte)0x10, (byte)0xf9, (byte)0xae, (byte)0xf7, (byte)0x14, (byte)0x27, (byte)0xe2,
		  (byte)0xfc, (byte)0x6f, (byte)0x9b, (byte)0x3f, (byte)0x39, (byte)0x9a, (byte)0x22, (byte)0x14, 
		  (byte)0x89, (byte)0xf1, (byte)0x63, (byte)0x62, (byte)0xc7, (byte)0x03, (byte)0x23, (byte)0x36,
		  (byte)0x09, (byte)0xd4, (byte)0x5a, (byte)0xc6, (byte)0x98, (byte)0x64, (byte)0xe3, (byte)0x32, 
		  (byte)0x1c, (byte)0xf8, (byte)0x29, (byte)0x35, (byte)0xac, (byte)0x40, (byte)0x96, (byte)0xc8,
		  (byte)0x6e, (byte)0x13, (byte)0x33, (byte)0x14, (byte)0xc5, (byte)0x40, (byte)0x19, (byte)0xe8, 
		  (byte)0xca, (byte)0x79, (byte)0x80, (byte)0xdf, (byte)0xa4, (byte)0xb9, (byte)0xcf, (byte)0x1b,
		  (byte)0x38, (byte)0x4c, (byte)0x48, (byte)0x6f, (byte)0x3a, (byte)0x54, (byte)0xc5, (byte)0x10, 
		  (byte)0x78, (byte)0x15, (byte)0x8e, (byte)0xe5, (byte)0xd7, (byte)0x9d, (byte)0xe5, (byte)0x9f,
		  (byte)0xbd, (byte)0x34, (byte)0xd8, (byte)0x48, (byte)0xb3, (byte)0xd6, (byte)0x95, (byte)0x50, 
		  (byte)0xa6, (byte)0x76, (byte)0x46, (byte)0x34, (byte)0x44, (byte)0x27, (byte)0xad, (byte)0xe5,
		  (byte)0x4b, (byte)0x88, (byte)0x51, (byte)0xff, (byte)0xb5, (byte)0x98, (byte)0xf7, (byte)0xf8, 
		  (byte)0x00, (byte)0x74, (byte)0xb9, (byte)0x47, (byte)0x3c, (byte)0x82, (byte)0xe2, (byte)0xdb  };


	private static final byte[] CIPHER_TEXT_512 = 
		{ (byte)0x4a, (byte)0xff, (byte)0xaa, (byte)0xad, (byte)0xb7, (byte)0x8c, (byte)0x31, (byte)0xc5, 
		  (byte)0xda, (byte)0x4b, (byte)0x1b, (byte)0x59, (byte)0x0d, (byte)0x10, (byte)0xff, (byte)0xbd,
		  (byte)0x3d, (byte)0xd8, (byte)0xd5, (byte)0xd3, (byte)0x02, (byte)0x42, (byte)0x35, (byte)0x26, 
		  (byte)0x91, (byte)0x2d, (byte)0xa0, (byte)0x37, (byte)0xec, (byte)0xbc, (byte)0xc7, (byte)0xbd,
		  (byte)0x82, (byte)0x2c, (byte)0x30, (byte)0x1d, (byte)0xd6, (byte)0x7c, (byte)0x37, (byte)0x3b, 
		  (byte)0xcc, (byte)0xb5, (byte)0x84, (byte)0xad, (byte)0x3e, (byte)0x92, (byte)0x79, (byte)0xc2,
		  (byte)0xe6, (byte)0xd1, (byte)0x2a, (byte)0x13, (byte)0x74, (byte)0xb7, (byte)0x7f, (byte)0x07, 
		  (byte)0x75, (byte)0x53, (byte)0xdf, (byte)0x82, (byte)0x94, (byte)0x10, (byte)0x44, (byte)0x6b,
		  (byte)0x36, (byte)0xeb, (byte)0xd9, (byte)0x70, (byte)0x66, (byte)0x29, (byte)0x6a, (byte)0xe6, 
		  (byte)0x42, (byte)0x7e, (byte)0xa7, (byte)0x5c, (byte)0x2e, (byte)0x08, (byte)0x46, (byte)0xa1,
		  (byte)0x1a, (byte)0x09, (byte)0xcc, (byte)0xf5, (byte)0x37, (byte)0x0d, (byte)0xc8, (byte)0x0b,
		  (byte)0xfe, (byte)0xcb, (byte)0xad, (byte)0x28, (byte)0xc7, (byte)0x3f, (byte)0x09, (byte)0xb3,
		  (byte)0xa3, (byte)0xb7, (byte)0x5e, (byte)0x66, (byte)0x2a, (byte)0x25, (byte)0x94, (byte)0x41, 
		  (byte)0x0a, (byte)0xe4, (byte)0x96, (byte)0xb2, (byte)0xe2, (byte)0xe6, (byte)0x60, (byte)0x9e,
		  (byte)0x31, (byte)0xe6, (byte)0xe0, (byte)0x2c, (byte)0xc8, (byte)0x37, (byte)0xf0, (byte)0x53, 
		  (byte)0xd2, (byte)0x1f, (byte)0x37, (byte)0xff, (byte)0x4f, (byte)0x51, (byte)0x95, (byte)0x0b,
		  (byte)0xbe, (byte)0x26, (byte)0x38, (byte)0xd0, (byte)0x9d, (byte)0xd7, (byte)0xa4, (byte)0x93, 
		  (byte)0x09, (byte)0x30, (byte)0x80, (byte)0x6d, (byte)0x07, (byte)0x03, (byte)0xb1, (byte)0xf6  };


	private static final byte[] AUTH_TAG_256 = 
		{ (byte)0x65, (byte)0x2c, (byte)0x3f, (byte)0xa3, (byte)0x6b, (byte)0x0a, (byte)0x7c, (byte)0x5b, 
		  (byte)0x32, (byte)0x19, (byte)0xfa, (byte)0xb3, (byte)0xa3, (byte)0x0b, (byte)0xc1, (byte)0xc4  };


	private static final byte[] AUTH_TAG_512 = 
		{ (byte)0x4d, (byte)0xd3, (byte)0xb4, (byte)0xc0, (byte)0x88, (byte)0xa7, (byte)0xf4, (byte)0x5c, 
		  (byte)0x21, (byte)0x68, (byte)0x39, (byte)0x64, (byte)0x5b, (byte)0x20, (byte)0x12, (byte)0xbf,
		  (byte)0x2e, (byte)0x62, (byte)0x69, (byte)0xa8, (byte)0xc5, (byte)0x6a, (byte)0x81, (byte)0x6d, 
		  (byte)0xbc, (byte)0x1b, (byte)0x26, (byte)0x77, (byte)0x61, (byte)0x95, (byte)0x5b, (byte)0xc5  };


	public void testAADLengthComputation()
		throws JOSEException {

		Assert.assertArrayEquals(AAD_LENGTH, com.nimbusds.jose.crypto.AAD.computeLength(AAD));
	}


	public void testAuthenticatedEncryption256()
		throws Exception {

		SecretKey inputKey = new SecretKeySpec(INPUT_KEY_256, "AES");

		Assert.assertArrayEquals("Input key", INPUT_KEY_256, inputKey.getEncoded());

		AuthenticatedCipherText act = AESCBC.encryptAuthenticated(inputKey, IV, PLAIN_TEXT, AAD, null, null);

		Assert.assertArrayEquals("Cipher text", CIPHER_TEXT_256, act.getCipherText());
		Assert.assertArrayEquals("Auth tag", AUTH_TAG_256, act.getAuthenticationTag());
	}


	public void testAuthenticatedEncryption512()
		throws Exception {

		SecretKey inputKey = new SecretKeySpec(INPUT_KEY_512, "AES");

		Assert.assertArrayEquals("Input key", INPUT_KEY_512, inputKey.getEncoded());

		AuthenticatedCipherText act = AESCBC.encryptAuthenticated(inputKey, IV, PLAIN_TEXT, AAD, null, null);

		Assert.assertArrayEquals("Cipher text", CIPHER_TEXT_512, act.getCipherText());
		Assert.assertArrayEquals("Auth tag", AUTH_TAG_512, act.getAuthenticationTag());
	}
	
	
	public void testCBCPaddingOracleAttack()
		throws Exception {
		
		SecretKey inputKey = new SecretKeySpec(INPUT_KEY_256, "AES");
		
		Assert.assertArrayEquals("Input key", INPUT_KEY_256, inputKey.getEncoded());
		
		AuthenticatedCipherText act = AESCBC.encryptAuthenticated(inputKey, IV, PLAIN_TEXT, AAD, null, null);
		
		byte[] cipherText = act.getCipherText();
		
		// Now change the cipher text to make CBC padding invalid.
		cipherText[cipherText.length - 1] ^= 0x01;
		
		try {
			AESCBC.decryptAuthenticated(inputKey, IV, cipherText, AAD, act.getAuthenticationTag(), null, null);
		} catch (JOSEException e) {
			assertEquals("MAC check failed", e.getMessage());
		}
	}
	
	
	public void testCBCPaddingOracleAttackOldConcatKDF()
		throws Exception {
		
		SecretKey inputKey = new SecretKeySpec(INPUT_KEY_256, "AES");
		
		Assert.assertArrayEquals("Input key", INPUT_KEY_256, inputKey.getEncoded());
		
		AuthenticatedCipherText act = AESCBC.encryptWithConcatKDF(
			new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256_DEPRECATED),
			new SecretKeySpec(INPUT_KEY_256, "AES"),
			Base64URL.encode(INPUT_KEY_256), // mock
			IV,
			PLAIN_TEXT,
			null,
			null
			);
		
		byte[] cipherText = act.getCipherText();
		
		// Now change the cipher text to make CBC padding invalid.
		cipherText[cipherText.length - 1] ^= 0x01;
		
		try {
			AESCBC.decryptWithConcatKDF(
				new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256_DEPRECATED),
				new SecretKeySpec(INPUT_KEY_256, "AES"),
				Base64URL.encode(INPUT_KEY_256), // mock
				Base64URL.encode(IV),
				Base64URL.encode(cipherText),
				Base64URL.encode(act.getAuthenticationTag()),
				null,
				null
			);
		} catch (JOSEException e) {
			assertEquals("MAC check failed", e.getMessage());
		}
	}
	
	
	public void testIntegerOverflowHmacBypass()
		throws Exception {
		
		SecretKey inputKey = new SecretKeySpec(INPUT_KEY_256, "AES");
		
		Assert.assertArrayEquals("Input key", INPUT_KEY_256, inputKey.getEncoded());
		byte[] iv = new byte[16];
		byte[] aad = new byte[8];
		byte[] plaintext = new byte[536870928];
		for (int i = 0; i < plaintext.length; i++ ){
			// Doesn't matter what value is, but rand is too expensive for large array
			plaintext[i] = (byte) i;
		}
		
		AuthenticatedCipherText act;
		
		try {
			act = AESCBC.encryptAuthenticated(inputKey, iv, plaintext, aad, null, null);
		} catch (OutOfMemoryError e) {
			System.out.println("Test not run due to " + e);
			return;
		}
		
		byte[] ciphertext = act.getCipherText();
		byte[] authTag = act.getAuthenticationTag();
		
		// Now shift aad and ciphertext around so that HMAC doesn't change,
		// but the plaintext will change.
		int n = 0;
		byte[] buffer = new byte[aad.length + iv.length + ciphertext.length];
		System.arraycopy(aad, 0, buffer, n, aad.length);
		n += aad.length;
		System.arraycopy(iv, 0, buffer, n, iv.length);
		n += iv.length;
		System.arraycopy(ciphertext, 0, buffer, n, ciphertext.length);
		// Note that due to integer overflow :536870920 * 8 = 64
		int newAadSize = 536870920;
		byte[] newAad = Arrays.copyOfRange(buffer, 0, newAadSize);
		byte[] newIv = Arrays.copyOfRange(buffer, newAadSize, newAadSize + 16);
		byte[] newCiphertext = Arrays.copyOfRange(buffer, newAadSize + 16,
			buffer.length);
		
		try {
			byte[] decrypted = AESCBC.decryptAuthenticated(inputKey, newIv,
				newCiphertext, newAad,
				authTag, // Note that the authTag does NOT change.
				null, null);
			// Reaching this point means that the HMac check is
			// bypassed although the decrypted data is different
			// from plaintext.
			// Assert.assertArrayEquals(decrypted, plaintext);
			fail();
		} catch (JOSEException ignored) {
			// ok
		}
	}
	
}