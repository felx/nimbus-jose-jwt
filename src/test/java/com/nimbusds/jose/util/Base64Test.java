package com.nimbusds.jose.util;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-13)
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


	public void testDecodeExampleKristina() {

		Base64 base64 = new Base64("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=");

		System.out.println(base64.decodeToString());

		base64 = new Base64("eyJleHAiOjM3NzQ4NjQwNSwiYXpwIjoiRFAwMWd5M1Frd1ZHR2RJZWpJSmdMWEN0UlRnYSIsInN1" +
			"YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6IkRQMDFneTNRa3dWR0dkSWVqSUpnTFhDdFJU" +
			"Z2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMmVuZHBvaW50c1wvdG9r" +
			"ZW4iLCJpYXQiOjM3Mzg4NjQwNX0=");

		System.out.println(base64.decodeToString());
	}
}

