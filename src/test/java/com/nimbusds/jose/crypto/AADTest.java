package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Arrays;

import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;


/**
 * Tests the Additional Authenticated Data (AAD) functions.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-17
 */
public class AADTest extends TestCase {


	public void testComputeForJWEHeader() {

		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		byte[] expected = jweHeader.toBase64URL().toString().getBytes(Charset.forName("ASCII"));

		assertTrue(Arrays.equals(expected, AAD.compute(jweHeader)));
	}


	public void testComputeForBase64URL() {

		Base64URL base64URL = Base64URL.encode("Hello world!");

		byte[] expected = base64URL.toString().getBytes(Charset.forName("ASCII"));

		assertTrue(Arrays.equals(expected, AAD.compute(base64URL)));
	}


	public void testComputeLength() {

		byte[] aad = new byte[]{0, 1, 2, 3}; // 32 bits

		byte[] expectedBitLength = new byte[]{0, 0, 0, 0, 0, 0, 0, 32};

		assertTrue(Arrays.equals(expectedBitLength, AAD.computeLength(aad)));
	}
}
