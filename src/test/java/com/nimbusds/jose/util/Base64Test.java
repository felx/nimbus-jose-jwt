package com.nimbusds.jose.util;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-13
 */
public class Base64Test extends TestCase {


	public void testEncode() {

		// Test vector from rfc4648#section-10
		Base64 b64 = Base64.encode("foobar");
		assertEquals("Zm9vYmFy", b64.toString());
	}


	public void testDecode() {

		// Test vector from rfc4648#section-10
		Base64 b64 = new Base64("Zm9vYmFy");
		assertEquals("foobar", b64.decodeToString());
	}


	public void testBigIntegerEncodeAndDecode() {
		
		BigInteger bigInt = new BigInteger("12345678901234567890");
		Base64 b64 = Base64.encode(bigInt);
		assertEquals(bigInt, b64.decodeToBigInteger());
	}
}

