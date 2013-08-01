package com.nimbusds.jwt;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;


/**
 * Tests the JWT parser. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-01)
 */
public class JWTParserTest extends TestCase {


	public void testParsePlainJWT()
		throws Exception {

		String s = "eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".";

		JWT jwt = JWTParser.parse(s);
		
		assertTrue(jwt instanceof PlainJWT);
		
		PlainJWT plainJWT = (PlainJWT)jwt;

		assertEquals(Algorithm.NONE, plainJWT.getHeader().getAlgorithm());
		assertNull(plainJWT.getHeader().getType());
		assertNull(plainJWT.getHeader().getContentType());

		ReadOnlyJWTClaimsSet cs = plainJWT.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380l * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getCustomClaim("http://example.com/is_root"));
	}
}
