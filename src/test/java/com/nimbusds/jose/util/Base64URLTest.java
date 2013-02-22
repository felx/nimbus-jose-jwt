package com.nimbusds.jose.util;


import java.io.UnsupportedEncodingException;

import junit.framework.TestCase;


public class Base64URLTest extends TestCase {


	// Test byte array
	byte[] bytes = {0x3, (byte)236, (byte)255, (byte)224, (byte)193};


	// Test JSON string
	String string = "{\"iss\":\"joe\",\r\n" +
			" \"exp\":1300819380,\r\n" +
			" \"http://example.com/is_root\":true}";


	public void testEncode() {

		assertEquals("A-z_4ME", Base64URL.encode(bytes).toString());
	}


	public void testDecode() {

		byte[] decoded = new Base64URL("A-z_4ME").decode();

		assertEquals(bytes.length, decoded.length);
		assertEquals(bytes[0], decoded[0]);
		assertEquals(bytes[1], decoded[1]);
		assertEquals(bytes[2], decoded[2]);
		assertEquals(bytes[3], decoded[3]);
	}


	public void testEncodeAndDecode() 
			throws UnsupportedEncodingException {

		byte[] bytes = string.getBytes("utf-8");

		Base64URL b64url = Base64URL.encode(bytes);

		String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		assertEquals(expected, b64url.toString());
	}
}

