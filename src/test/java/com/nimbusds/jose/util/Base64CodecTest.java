package com.nimbusds.jose.util;


import java.nio.charset.Charset;

import com.nimbusds.jose.util.Base64Codec;
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


	public void testNormalizeWithIllegalChars(){

		assertEquals("Zg\n==", Base64Codec.normalizeEncodedString("Zg\n"));
		assertEquals("Zm\n8=", Base64Codec.normalizeEncodedString("Zm\n8"));
		assertEquals("Zm\n9v\n", Base64Codec.normalizeEncodedString("Zm\n9v\n"));
		assertEquals("Zm\n9v\nYg\n==", Base64Codec.normalizeEncodedString("Zm\n9v\nYg\n"));
		assertEquals("Zm\n9v\nYm\nE=", Base64Codec.normalizeEncodedString("Zm\n9v\nYm\nE"));
		assertEquals("Zm\n9v\nYm\nFy", Base64Codec.normalizeEncodedString("Zm\n9v\nYm\nFy"));
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


	public void testDecodeWithIllegalChars() {

		assertEquals("", new String(Base64Codec.decode("\n"), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg==\n"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8=\n"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v\n"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg==\n"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE=\n"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy\n"), Charset.forName("utf-8")));
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


	public void testDecodeUrlSafeWithIllegalChars() {

		assertEquals("", new String(Base64Codec.decode("\n"), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg\n"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8\n"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v\n"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg\n"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE\n"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy\n"), Charset.forName("utf-8")));
	}


	public void testCountIllegalChars() {

		assertEquals(0, Base64Codec.countIllegalChars(""));
		assertEquals(0, Base64Codec.countIllegalChars("Zg"));
		assertEquals(1, Base64Codec.countIllegalChars("Zg\n"));
		assertEquals(2, Base64Codec.countIllegalChars("Zg\r\n"));

		assertEquals(0, Base64Codec.countIllegalChars("Zg=="));
		assertEquals(1, Base64Codec.countIllegalChars("Zg==\n"));
		assertEquals(2, Base64Codec.countIllegalChars("Zg==\r\n"));

		assertEquals(0, Base64Codec.countIllegalChars("Zm9vYmFy"));
		assertEquals(2, Base64Codec.countIllegalChars("Zm9v\nYmFy\n"));
		assertEquals(4, Base64Codec.countIllegalChars("Zm9v\r\nYmFy\r\n"));
	}
}
