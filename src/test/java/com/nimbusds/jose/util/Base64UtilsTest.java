package com.nimbusds.jose.util;


import java.nio.charset.Charset;

import junit.framework.TestCase;


/**
 * Tests the base64 utility.
 */
public class Base64UtilsTest extends TestCase {


	public void testComputeEncodedLength() {

		boolean urlSafe = false;
		assertEquals(0, Base64Utils.computeEncodedLength(0, urlSafe));
		assertEquals(4, Base64Utils.computeEncodedLength(1, urlSafe));
		assertEquals(4, Base64Utils.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Utils.computeEncodedLength(3, urlSafe));
		assertEquals(8, Base64Utils.computeEncodedLength(4, urlSafe));
		assertEquals(8, Base64Utils.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Utils.computeEncodedLength(6, urlSafe));

		urlSafe = true;
		assertEquals(0, Base64Utils.computeEncodedLength(0, urlSafe));
		assertEquals(2, Base64Utils.computeEncodedLength(1, urlSafe));
		assertEquals(3, Base64Utils.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Utils.computeEncodedLength(3, urlSafe));
		assertEquals(6, Base64Utils.computeEncodedLength(4, urlSafe));
		assertEquals(7, Base64Utils.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Utils.computeEncodedLength(6, urlSafe));
	}


	public void testEncode() {

		// Test vectors from rfc4648#section-10
		assertEquals("", Base64Utils.encodeToString("".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zg==", Base64Utils.encodeToString("f".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm8=", Base64Utils.encodeToString("fo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9v", Base64Utils.encodeToString("foo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYg==", Base64Utils.encodeToString("foob".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmE=", Base64Utils.encodeToString("fooba".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmFy", Base64Utils.encodeToString("foobar".getBytes(Charset.forName("utf-8")), false));
	}


	public void testEncodeUrlSafe() {

		// Test vectors from rfc4648#section-10 with stripped padding
		assertEquals("", Base64Utils.encodeToString("".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zg", Base64Utils.encodeToString("f".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm8", Base64Utils.encodeToString("fo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9v", Base64Utils.encodeToString("foo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYg", Base64Utils.encodeToString("foob".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmE", Base64Utils.encodeToString("fooba".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmFy", Base64Utils.encodeToString("foobar".getBytes(Charset.forName("utf-8")), true));
	}
}
