package com.nimbusds.jose.util;


import java.nio.charset.Charset;

import junit.framework.TestCase;


/**
 * Tests the base 64 codec.
 */
public class Base64CodecTest extends TestCase {


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


	public void testNormalize(){

		assertEquals("Zg==", Base64Codec.normalizeEncodedString("Zg"));
		assertEquals("Zm8=", Base64Codec.normalizeEncodedString("Zm8"));
		assertEquals("Zm9v", Base64Codec.normalizeEncodedString("Zm9v"));
		assertEquals("Zm9vYg==", Base64Codec.normalizeEncodedString("Zm9vYg"));
		assertEquals("Zm9vYmE=", Base64Codec.normalizeEncodedString("Zm9vYmE"));
		assertEquals("Zm9vYmFy", Base64Codec.normalizeEncodedString("Zm9vYmFy"));
	}


	public void testDecode() {

		assertEquals("", new String(Base64Codec.decode(""), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg=="), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8="), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg=="), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE="), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy"), Charset.forName("utf-8")));
	}


	public void testDecodeUrlSafe() {

		assertEquals("", new String(Base64Codec.decode(""), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy"), Charset.forName("utf-8")));
	}
}
