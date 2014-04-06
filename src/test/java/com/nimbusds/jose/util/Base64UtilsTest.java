package com.nimbusds.jose.util;


import java.nio.charset.Charset;

import junit.framework.TestCase;


/**
 * Tests the base64 utility.
 */
public class Base64UtilsTest extends TestCase {


	public void testComputeEncodedLength() {

		boolean urlSafe = false;
		assertEquals(0, Base64Codec.computeEncodedLength(0, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(1, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(3, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(4, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(6, urlSafe));

		urlSafe = true;
		assertEquals(0, Base64Codec.computeEncodedLength(0, urlSafe));
		assertEquals(2, Base64Codec.computeEncodedLength(1, urlSafe));
		assertEquals(3, Base64Codec.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(3, urlSafe));
		assertEquals(6, Base64Codec.computeEncodedLength(4, urlSafe));
		assertEquals(7, Base64Codec.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(6, urlSafe));
	}


	public void testEncode() {

		// Test vectors from rfc4648#section-10
		assertEquals("", Base64Codec.encodeToString("".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zg==", Base64Codec.encodeToString("f".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm8=", Base64Codec.encodeToString("fo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9v", Base64Codec.encodeToString("foo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYg==", Base64Codec.encodeToString("foob".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmE=", Base64Codec.encodeToString("fooba".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmFy", Base64Codec.encodeToString("foobar".getBytes(Charset.forName("utf-8")), false));
	}


	public void testEncodeUrlSafe() {

		// Test vectors from rfc4648#section-10 with stripped padding
		assertEquals("", Base64Codec.encodeToString("".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zg", Base64Codec.encodeToString("f".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm8", Base64Codec.encodeToString("fo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9v", Base64Codec.encodeToString("foo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYg", Base64Codec.encodeToString("foob".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmE", Base64Codec.encodeToString("fooba".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmFy", Base64Codec.encodeToString("foobar".getBytes(Charset.forName("utf-8")), true));
	}
}
