/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.util;


import java.math.BigInteger;
import java.nio.charset.Charset;

import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
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


	public void testEncodeAndDecode() {

		byte[] bytes = STRING.getBytes(Charset.forName("utf-8"));

		Base64URL b64url = Base64URL.encode(bytes);

		String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		assertEquals(expected, b64url.toString());
	}


	public void testBigIntegerEncodeAndDecode() {
		
		Base64URL b64url = Base64URL.encode(BIGINT);

		assertEquals(BIGINT, b64url.decodeToBigInteger());
	}
}

