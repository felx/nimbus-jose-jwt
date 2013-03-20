package com.nimbusds.jose.util;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-20)
 */
public class Base64URLTest extends TestCase {


	// Test byte array
	private static final byte[] BYTES = {0x3, (byte)236, (byte)255, (byte)224, (byte)193};


	// Test JSON string
	private static final String STRING = "{\"iss\":\"joe\",\r\n" +
			                     " \"exp\":1300819380,\r\n" +
			                     " \"http://example.com/is_root\":true}";
                     

	// Test big integer
	private static final BigInteger BIGINT = new BigInteger("9999999999999999999999999999999999");


	// Test base64URL string
	private static final Base64URL B64URL = new Base64URL(
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
		"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
		"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
		"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
		"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");


	public void testByteArrayEncodeAndDecode() {

		assertEquals("A-z_4ME", Base64URL.encode(BYTES).toString());

		byte[] decoded = new Base64URL("A-z_4ME").decode();

		assertEquals(BYTES.length, decoded.length);
		assertEquals(BYTES[0], decoded[0]);
		assertEquals(BYTES[1], decoded[1]);
		assertEquals(BYTES[2], decoded[2]);
		assertEquals(BYTES[3], decoded[3]);
	}


	public void testEncodeAndDecode() 
		throws UnsupportedEncodingException {

		byte[] bytes = STRING.getBytes("utf-8");

		Base64URL b64url = Base64URL.encode(bytes);

		String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		assertEquals(expected, b64url.toString());
	}


	public void testBigIntegerEncodeAndDecode() {
		
		Base64URL b64url = Base64URL.encode(BIGINT);

		assertEquals(BIGINT, b64url.decodeToBigInteger());
	}


	public void testBase64URLBigIntegerEncodeAndDecode() {

		BigInteger bigInt = B64URL.decodeToBigInteger();

		assertEquals(B64URL, Base64URL.encode(bigInt));
	}
}

