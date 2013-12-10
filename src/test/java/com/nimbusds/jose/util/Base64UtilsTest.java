package com.nimbusds.jose.util;


import java.nio.charset.Charset;

import junit.framework.TestCase;


/**
 * Tests the base64 utility.
 */
public class Base64UtilsTest extends TestCase {


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
}
