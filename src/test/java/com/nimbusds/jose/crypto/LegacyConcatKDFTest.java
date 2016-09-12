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


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.util.Arrays;

import com.nimbusds.jose.EncryptionMethod;


/**
 * Tests the Concatenation KDF for CEK and CIK generation. Test vectors from
 * draft-ietf-jose-json-web-encryption-08
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-12
 */
public class LegacyConcatKDFTest extends TestCase {


	// The input 256 bit CMK
	private final static byte[] cmk256 = {

		(byte)  4, (byte)211, (byte) 31, (byte)197, (byte) 84, (byte)157, (byte)252, (byte)254,
		(byte) 11, (byte)100, (byte)157, (byte)250, (byte) 63, (byte)170, (byte)106, (byte)206,
		(byte)107, (byte)124, (byte)212, (byte) 45, (byte)111, (byte)107, (byte)  9, (byte)219,
		(byte)200, (byte)177, (byte)  0, (byte)240, (byte)143, (byte)156, (byte) 44, (byte)207
	};


	// The expected 128 bit CEK
	private final static byte[] cek128 = {

		(byte)203, (byte)165, (byte)180, (byte)113, (byte) 62, (byte)195, (byte) 22, (byte) 98,
		(byte) 91, (byte)153, (byte)210, (byte) 38, (byte)112, (byte) 35, (byte)230, (byte)236
	};


	// The expected 256 bit CIK
	private final static byte[] cik256 = {

		(byte)218, (byte) 24, (byte)160, (byte) 17, (byte)160, (byte) 50, (byte)235, (byte) 35,
		(byte)216, (byte)209, (byte)100, (byte)174, (byte)155, (byte)163, (byte) 10, (byte)117,
		(byte)180, (byte)111, (byte)172, (byte)200, (byte)127, (byte)201, (byte)206, (byte)173,
		(byte) 40, (byte) 45, (byte) 58, (byte)170, (byte) 35, (byte) 93, (byte)  9, (byte) 60
	};


	// The input 512 bit CMK
	private final static byte[] cmk512 = {

		(byte)148, (byte)116, (byte)199, (byte)126, (byte)  2, (byte)117, (byte)233, (byte) 76,
		(byte)150, (byte)149, (byte) 89, (byte)193, (byte) 61, (byte) 34, (byte)239, (byte)226,
		(byte)109, (byte) 71, (byte) 59, (byte)160, (byte)192, (byte)140, (byte)150, (byte)235,
		(byte)106, (byte)204, (byte) 49, (byte)176, (byte) 68, (byte)119, (byte) 13, (byte) 34,
		(byte) 49, (byte) 19, (byte) 41, (byte) 69, (byte)  5, (byte) 20, (byte)252, (byte)145,
		(byte)104, (byte)129, (byte)137, (byte)138, (byte) 67, (byte) 23, (byte)153, (byte) 83,
		(byte) 81, (byte)234, (byte) 82, (byte)247, (byte) 48, (byte)211, (byte) 41, (byte)130,
		(byte) 35, (byte)124, (byte) 45, (byte)156, (byte)249, (byte)  7, (byte)225, (byte)168
	};


	// The expected 256 bit CEK
	private final static byte[] cek256 = {

		(byte)157, (byte) 19, (byte) 75, (byte)205, (byte) 31, (byte)190, (byte)110, (byte) 46,
		(byte)117, (byte)217, (byte)137, (byte) 19, (byte)116, (byte)166, (byte)126, (byte) 60,
		(byte) 18, (byte)244, (byte)226, (byte)114, (byte) 38, (byte)153, (byte) 78, (byte)198,
		(byte) 26, (byte)  0, (byte)181, (byte)168, (byte)113, (byte) 45, (byte)149, (byte) 89
	};


	// The expected 512 bit CIK
	private final static byte[] cik512 = {

		(byte) 81, (byte)249, (byte)131, (byte)194, (byte) 25, (byte)166, (byte)147, (byte)155,
		(byte) 47, (byte)249, (byte)146, (byte)160, (byte)200, (byte)236, (byte)115, (byte) 72,
		(byte)103, (byte)248, (byte)228, (byte) 30, (byte)130, (byte)225, (byte)164, (byte) 61,
		(byte)105, (byte)172, (byte)198, (byte) 31, (byte)137, (byte)170, (byte)215, (byte)141,
		(byte) 27, (byte)247, (byte) 73, (byte)236, (byte)125, (byte)113, (byte)151, (byte) 33,
		(byte)  0, (byte)251, (byte) 72, (byte) 53, (byte) 72, (byte) 63, (byte)146, (byte)117,
		(byte)247, (byte) 13, (byte) 49, (byte) 20, (byte)210, (byte)169, (byte)232, (byte)156,
		(byte)118, (byte)  1, (byte) 16, (byte) 45, (byte) 29, (byte) 21, (byte) 15, (byte)208
	};


	public void testGenerateCEK128()
		throws Exception {

		SecretKey cmk = new SecretKeySpec(cmk256, "AES");

		SecretKey computedCEK = LegacyConcatKDF.generateCEK(cmk, EncryptionMethod.A128CBC_HS256_DEPRECATED, null, null);

		assertEquals(128, computedCEK.getEncoded().length * 8);

		assertTrue(Arrays.constantTimeAreEqual(cek128, computedCEK.getEncoded()));
	}


	public void testGenerateCIK256()
		throws Exception {

		SecretKey cmk = new SecretKeySpec(cmk256, "AES");

		SecretKey computedCIK = LegacyConcatKDF.generateCIK(cmk, EncryptionMethod.A128CBC_HS256_DEPRECATED, null, null);

		assertEquals(256, computedCIK.getEncoded().length * 8);

		assertTrue(Arrays.constantTimeAreEqual(cik256, computedCIK.getEncoded()));
	}


	public void testGenerateCEK256()
		throws Exception {

		SecretKey cmk = new SecretKeySpec(cmk512, "AES");

		SecretKey computedCEK = LegacyConcatKDF.generateCEK(cmk, EncryptionMethod.A256CBC_HS512_DEPRECATED, null, null);

		assertEquals(256, computedCEK.getEncoded().length * 8);

		assertTrue(Arrays.constantTimeAreEqual(cek256, computedCEK.getEncoded()));
	}


	public void testGenerateCIK512()
		throws Exception {

		SecretKey cmk = new SecretKeySpec(cmk512, "AES");

		SecretKey computedCIK = LegacyConcatKDF.generateCIK(cmk, EncryptionMethod.A256CBC_HS512_DEPRECATED, null, null);

		assertEquals(512, computedCIK.getEncoded().length * 8);

		assertTrue(Arrays.constantTimeAreEqual(cik512, computedCIK.getEncoded()));
	}
}
