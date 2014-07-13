package com.nimbusds.jwt;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests plain JWT object. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-13)
 */
public class PlainJWTTest extends TestCase {


	public void testBase64URLConstructor()
		throws Exception {

		// {"alg":"none"}
		Base64URL part1 = new Base64URL("eyJhbGciOiJub25lIn0");

		// {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
		Base64URL part2 = new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

		PlainJWT jwt = new PlainJWT(part1, part2);

		assertEquals(Algorithm.NONE, jwt.getHeader().getAlgorithm());
		assertNull(jwt.getHeader().getType());
		assertNull(jwt.getHeader().getContentType());

		ReadOnlyJWTClaimsSet cs = jwt.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380l * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getCustomClaim("http://example.com/is_root"));
	}


	public void testParse()
		throws Exception {

		String s = "eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".";

		PlainJWT jwt = PlainJWT.parse(s);

		assertEquals(Algorithm.NONE, jwt.getHeader().getAlgorithm());
		assertNull(jwt.getHeader().getType());
		assertNull(jwt.getHeader().getContentType());

		ReadOnlyJWTClaimsSet cs = jwt.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380l * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getCustomClaim("http://example.com/is_root"));
	}





	public void testExampleKristina()
		throws Exception {

		String jwtString = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=" +
			".eyJleHAiOjM3NzQ4NjQwNSwiYXpwIjoiRFAwMWd5M1Frd1ZHR2RJZWpJSmdMWEN0UlRnYSIsInN1" +
			"YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6IkRQMDFneTNRa3dWR0dkSWVqSUpnTFhDdFJU" +
			"Z2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMmVuZHBvaW50c1wvdG9r" +
			"ZW4iLCJpYXQiOjM3Mzg4NjQwNX0=" +
			".";

		PlainJWT plainJWT = PlainJWT.parse(jwtString);

		System.out.println(plainJWT.getHeader().toJSONObject());
		System.out.println(plainJWT.getJWTClaimsSet().toJSONObject());
	}
}
