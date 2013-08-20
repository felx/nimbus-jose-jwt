package com.nimbusds.jose;


import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Tests the base JOSE header class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
 */
public class HeaderTest extends TestCase {


	public void testParsePlainHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWT spec
		Base64URL in = new Base64URL("eyJhbGciOiJub25lIn0");

		Header header = Header.parse(in);

		assertTrue(header instanceof PlainHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(Algorithm.NONE, header.getAlgorithm());
	}


	public void testParseJWSHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWS spec
		Base64URL in = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

		Header header = Header.parse(in);

		assertTrue(header instanceof JWSHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());
	}


	public void testParseJWEHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWE spec
		Base64URL in = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

		Header header = Header.parse(in);

		assertTrue(header instanceof JWEHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(JWEAlgorithm.RSA1_5, header.getAlgorithm());

		JWEHeader jweHeader = (JWEHeader)header;
		assertEquals(EncryptionMethod.A128CBC_HS256, jweHeader.getEncryptionMethod());
	}
}
