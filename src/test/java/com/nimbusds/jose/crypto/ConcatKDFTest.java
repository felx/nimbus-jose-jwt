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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.IntegerUtils;
import junit.framework.TestCase;


/**
 * Tests the Concatenation KDF.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-05-05
 */
public class ConcatKDFTest extends TestCase {
	
	
	public void testComposeOtherInfo() {
		
		// From http://tools.ietf.org/html/rfc7518#appendix-C
		
		String algId = "A128GCM";
		String producer = "Alice";
		String consumer = "Bob";
		int pubInfo = 128;
		
		byte[] otherInfo = ConcatKDF.composeOtherInfo(
			ConcatKDF.encodeStringData(algId),
			ConcatKDF.encodeStringData(producer),
			ConcatKDF.encodeStringData(consumer),
			ConcatKDF.encodeIntData(pubInfo),
			ConcatKDF.encodeNoData());
		
		byte[] expected = {
			(byte) 0, (byte) 0, (byte) 0, (byte) 7, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 71, (byte) 67, (byte) 77, (byte) 0, (byte) 0, (byte) 0, (byte) 5, (byte) 65,
			(byte) 108, (byte) 105, (byte) 99, (byte) 101, (byte) 0, (byte) 0, (byte) 0, (byte) 3,
			(byte) 66, (byte) 111, (byte) 98, (byte) 0, (byte) 0, (byte) 0, (byte) 128
		};
		
		assertTrue(Arrays.equals(expected, otherInfo));
	}
	
	
	public void testECDHVector()
		throws Exception {
		
		// From http://tools.ietf.org/html/rfc7518#appendix-C
		
		byte[] Z = {
			(byte) 158, (byte) 86, (byte) 217, (byte) 29, (byte) 129, (byte) 113, (byte) 53, (byte) 211,
			(byte) 114, (byte) 131, (byte) 66, (byte) 131, (byte) 191, (byte) 132, (byte) 38, (byte) 156,
			(byte) 251, (byte) 49, (byte) 110, (byte) 163, (byte) 218, (byte) 128, (byte) 106, (byte) 72,
			(byte) 246, (byte) 218, (byte) 167, (byte) 121, (byte) 140, (byte) 254, (byte) 144, (byte) 196
		};
		
		int keyLength = 128;
		String algId = "A128GCM";
		String producer = "Alice";
		String consumer = "Bob";
		int pubInfo = 128;
		
		ConcatKDF concatKDF = new ConcatKDF("SHA-256");
		
		assertEquals("SHA-256", concatKDF.getHashAlgorithm());
		
		SecretKey derivedKey = concatKDF.deriveKey(
			new SecretKeySpec(Z, "AES"),
			keyLength,
			ConcatKDF.encodeStringData(algId),
			ConcatKDF.encodeStringData(producer),
			ConcatKDF.encodeStringData(consumer),
			ConcatKDF.encodeIntData(pubInfo),
			ConcatKDF.encodeNoData());
		
		assertEquals(128, derivedKey.getEncoded().length * 8);
		
		byte[] expectedDerivedKey = {
			(byte) 86, (byte) 170, (byte) 141, (byte) 234, (byte) 248, (byte) 35, (byte) 109, (byte) 32,
			(byte) 92, (byte) 34, (byte) 40, (byte) 205, (byte) 113, (byte) 167, (byte) 16, (byte) 26};
		
		assertTrue(Arrays.equals(expectedDerivedKey, derivedKey.getEncoded()));
	}
	
	
	public void testComputeDigestCycles1() {
		
		int digestLength = 256;
		int keyLength = 521;
		
		assertEquals(3, ConcatKDF.computeDigestCycles(digestLength, keyLength));
	}
	
	
	public void testComputeDigestCycles2() {
		
		int digestLength = 256;
		int keyLength = 128;
		
		assertEquals(1, ConcatKDF.computeDigestCycles(digestLength, keyLength));
	}
	
	
	public void testEncodeNoData() {
		
		byte[] out = ConcatKDF.encodeNoData();
		
		assertEquals(0, out.length);
	}
	
	
	public void testEncodeIntData() {
		
		byte[] out = ConcatKDF.encodeIntData(1);
		
		assertTrue(Arrays.equals(new byte[]{0, 0, 0, 1}, out));
	}
	
	
	public void testEncodeStringData() {
		
		byte[] out = ConcatKDF.encodeStringData("Hello world!");
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertTrue(Arrays.equals(IntegerUtils.toBytes("Hello world!".length()), length));
		
		byte[] chars = ByteUtils.subArray(out, 4, out.length - 4);
		assertTrue(Arrays.equals("Hello world!".getBytes(Charset.forName("UTF-8")), chars));
	}
	
	
	public void testEncodeDataWithLength() {
		
		byte[] out = ConcatKDF.encodeDataWithLength(new byte[]{0, 1, 2, 3});
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertTrue(Arrays.equals(IntegerUtils.toBytes(4), length));
		
		byte[] data = ByteUtils.subArray(out, 4, out.length - 4);
		assertTrue(Arrays.equals(new byte[]{0, 1, 2, 3}, data));
	}
	
	
	public void testEncodeBase64URLDataWithLength() {
		
		byte[] out = ConcatKDF.encodeDataWithLength(Base64URL.encode(new byte[]{0, 1, 2, 3}));
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertTrue(Arrays.equals(IntegerUtils.toBytes(4), length));
		
		byte[] data = ByteUtils.subArray(out, 4, out.length - 4);
		assertTrue(Arrays.equals(new byte[]{0, 1, 2, 3}, data));
	}
	
	
	public void testKeyDerivation()
		throws Exception {
		
		ConcatKDF concatKDF = new ConcatKDF("SHA-256");
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey sharedKey = keyGenerator.generateKey();
		
		SecretKey derivedKey128 = concatKDF.deriveKey(sharedKey, 128, null);
		assertEquals(128, ByteUtils.bitLength(derivedKey128.getEncoded().length));
		
		SecretKey derivedKey256 = concatKDF.deriveKey(sharedKey, 256, null);
		assertEquals(256, ByteUtils.bitLength(derivedKey256.getEncoded().length));
	}
	
	
	public void testComputeDigestCycles()
		throws Exception {
		
		assertEquals(1, ConcatKDF.computeDigestCycles(256, 128));
		assertEquals(1, ConcatKDF.computeDigestCycles(384, 128));
		assertEquals(1, ConcatKDF.computeDigestCycles(512, 128));
		
		assertEquals(1, ConcatKDF.computeDigestCycles(256, 256));
		assertEquals(1, ConcatKDF.computeDigestCycles(384, 256));
		assertEquals(1, ConcatKDF.computeDigestCycles(512, 256));
		
		assertEquals(2, ConcatKDF.computeDigestCycles(256, 384));
		assertEquals(1, ConcatKDF.computeDigestCycles(384, 384));
		assertEquals(1, ConcatKDF.computeDigestCycles(512, 384));
		
		assertEquals(2, ConcatKDF.computeDigestCycles(256, 512));
		assertEquals(2, ConcatKDF.computeDigestCycles(384, 512));
		assertEquals(1, ConcatKDF.computeDigestCycles(512, 512));
	}
}