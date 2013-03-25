package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;

import junit.framework.TestCase;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.Arrays;

import com.nimbusds.jose.util.Base64;


/**
 * Tests Content Encoding Key (CEK) generation. Test vectors from
 * draft-ietf-jose-json-web-encryption-08
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-25)
 */
public class CEKTest extends TestCase {


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


	public void testGenerateFromCMK256()
		throws Exception {

		final int cekBitLength = 128;

		SecretKey computedCEK = CEK.generate(cmk256, cekBitLength, new SHA256Digest(), "A128CBC+HS256");

		System.out.println(Base64.encode(cek128));

		assertTrue(Arrays.constantTimeAreEqual(cek128, computedCEK.getEncoded()));
	}


	public void testGenerateFromCMK512()
		throws Exception {

		final int cekBitLength = 256;

		SecretKey computedCEK = CEK.generate(cmk512, cekBitLength, new SHA512Digest(), "A256CBC+HS512");

		System.out.println(Base64.encode(cek256));

		assertTrue(Arrays.constantTimeAreEqual(cek256, computedCEK.getEncoded()));
	}
}