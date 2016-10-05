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

import junit.framework.TestCase;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;


/**
 * Tests the PBKDF2 static methods.
 */
public class PBKDF2Test extends TestCase {


	public void testZeroByteConstant() {

		assertEquals((byte)0, PBKDF2.ZERO_BYTE[0]);
		assertEquals(1, PBKDF2.ZERO_BYTE.length);
	}


	public void testSaltFormat()
		throws Exception {

		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;

		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);

		byte[] expectedFormattedSalt = ByteUtils.concat(
			alg.toString().getBytes(Charset.forName("UTF-8")),
			PBKDF2.ZERO_BYTE,
			salt);

		assertTrue(Arrays.equals(expectedFormattedSalt, formattedSalt));
	}


	// From http://tools.ietf.org/html/rfc7517#appendix-C
	public void testSaltFormatVector()
		throws Exception {

		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;

		final byte[] random = {
			(byte)217, (byte)96, (byte)147, (byte)112, (byte)150, (byte)117, (byte)70, (byte)247,
			(byte)127, (byte) 8, (byte)155, (byte)137, (byte)174, (byte) 42, (byte)80, (byte)215 };

		assertEquals("2WCTcJZ1Rvd_CJuJripQ1w", Base64URL.encode(random).toString());

		byte[] concatSalt = PBKDF2.formatSalt(alg, random);

		final byte[] expectedConcatSalt = {
			(byte) 80, (byte) 66, (byte) 69, (byte) 83, (byte) 50, (byte) 45, (byte) 72, (byte) 83,
			(byte) 50, (byte) 53, (byte) 54, (byte) 43, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 75, (byte) 87, (byte)  0, (byte)217, (byte) 96, (byte)147, (byte)112, (byte)150,
			(byte)117, (byte) 70, (byte)247, (byte)127, (byte)  8, (byte)155, (byte)137, (byte)174,
			(byte) 42, (byte) 80, (byte)215 };

		assertTrue(Arrays.equals(expectedConcatSalt, concatSalt));
	}


	// From http://tools.ietf.org/html/rfc7517#appendix-C
	public void testDeriveKeyExample()
		throws Exception {

		final byte[] password = "Thus from my lips, by yours, my sin is purged.".getBytes(Charset.forName("UTF-8"));
		final byte[] salt = {
			(byte) 80, (byte) 66, (byte) 69, (byte) 83, (byte) 50, (byte) 45, (byte) 72, (byte) 83,
			(byte) 50, (byte) 53, (byte) 54, (byte) 43, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 75, (byte) 87, (byte)  0, (byte)217, (byte) 96, (byte)147, (byte)112, (byte)150,
			(byte)117, (byte) 70, (byte)247, (byte)127, (byte)  8, (byte)155, (byte)137, (byte)174,
			(byte) 42, (byte) 80, (byte)215 };

		// System.out.println(new String(salt, Charset.forName("UTF-8")));
		final int iterationCount = 4096;
		final int dkLen = 16;

		SecretKey secretKey = PBKDF2.deriveKey(password, salt, iterationCount, new PRFParams("HmacSHA256", null, dkLen));

		assertEquals(dkLen, secretKey.getEncoded().length);

		final byte[] expectedKey = {
			(byte)110, (byte)171, (byte)169, (byte) 92, (byte)129, (byte) 92, (byte)109, (byte)117,
			(byte)233, (byte)242, (byte)116, (byte)233, (byte)170, (byte) 14, (byte) 24, (byte) 75 };

		assertTrue(Arrays.equals(expectedKey, secretKey.getEncoded()));
	}
}
