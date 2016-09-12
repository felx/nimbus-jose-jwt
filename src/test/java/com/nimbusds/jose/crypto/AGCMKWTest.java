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


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * General AxxxGCMKW tests.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-19
 */
public class AGCMKWTest extends TestCase {


	// 128-bit shared symmetric key
	private final static byte[] key128 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226 };


	public void testRejectMissingHeaderIVParameter()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(
			JWEAlgorithm.A128GCMKW, EncryptionMethod.A128GCM).
			authTag(new Base64URL("abc")).
			build();

		Base64URL encryptedKey = new Base64URL("abc");
		Base64URL iv = new Base64URL("def");
		Base64URL cipherText = new Base64URL("ghi");
		Base64URL authTag = new Base64URL("jkl");

		AESDecrypter decrypter = new AESDecrypter(key128);

		try {
			decrypter.decrypt(header, encryptedKey, iv, cipherText, authTag);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing JWE \"iv\" header parameter", e.getMessage());
		}
	}

	public void testRejectMissingHeaderAuthTagParameter()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(
			JWEAlgorithm.A128GCMKW, EncryptionMethod.A128GCM).
			iv(new Base64URL("abc")).
			build();

		Base64URL encryptedKey = new Base64URL("abc");
		Base64URL iv = new Base64URL("def");
		Base64URL cipherText = new Base64URL("ghi");
		Base64URL authTag = new Base64URL("jkl");

		AESDecrypter decrypter = new AESDecrypter(key128);

		try {
			decrypter.decrypt(header, encryptedKey, iv, cipherText, authTag);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing JWE \"tag\" header parameter", e.getMessage());
		}
	}
}
