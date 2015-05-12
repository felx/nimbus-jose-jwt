package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.util.Arrays;


/**
 * Tests the Concatenation KDF.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-12)
 */
public class ConcatKDFTest extends TestCase {


	public void testComposeOtherInfo()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#appendix-C

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
			(byte)  0, (byte)  0, (byte)  0, (byte)  7, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 71, (byte) 67, (byte) 77, (byte)  0, (byte)  0, (byte)  0, (byte)  5, (byte) 65,
			(byte)108, (byte)105, (byte) 99, (byte)101, (byte)  0, (byte)  0, (byte)  0, (byte)  3,
			(byte) 66, (byte)111, (byte) 98, (byte)  0, (byte)  0, (byte) 0, (byte) 128
		};

		assertTrue(Arrays.areEqual(expected, otherInfo));
	}


	public void testECDHVector()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#appendix-C

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
			(byte) 86, (byte)170, (byte)141, (byte)234, (byte)248, (byte) 35, (byte)109, (byte) 32,
			(byte) 92, (byte) 34, (byte) 40, (byte)205, (byte)113, (byte)167, (byte) 16, (byte) 26 };

		assertTrue(Arrays.areEqual(expectedDerivedKey, derivedKey.getEncoded()));
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
}