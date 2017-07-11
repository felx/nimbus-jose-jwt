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

package com.nimbusds.jwt;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests plain JWT object. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-07-11
 */
public class PlainJWTTest extends TestCase {


	public void testClaimsSetConstructor()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer("http://c2id.com")
			.audience("http://app.example.com")
			.build();

		JWTClaimsSet readOnlyClaimsSet = claimsSet;
		
		PlainJWT jwt = new PlainJWT(readOnlyClaimsSet);

		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
		assertEquals("http://c2id.com", jwt.getJWTClaimsSet().getIssuer());
		assertEquals("http://app.example.com", jwt.getJWTClaimsSet().getAudience().get(0));
	}


	public void testHeaderAndClaimsSetConstructor()
		throws Exception {

		PlainHeader header = new PlainHeader.Builder().customParam("exp", 1000L).build();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer("http://c2id.com")
			.audience("http://app.example.com")
			.build();

		JWTClaimsSet readOnlyClaimsSet = claimsSet;

		PlainJWT jwt = new PlainJWT(header, readOnlyClaimsSet);

		assertEquals(header, jwt.getHeader());

		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
		assertEquals("http://c2id.com", jwt.getJWTClaimsSet().getIssuer());
		assertEquals("http://app.example.com", jwt.getJWTClaimsSet().getAudience().get(0));
	}


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

		JWTClaimsSet cs = jwt.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380L * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getClaim("http://example.com/is_root"));
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

		JWTClaimsSet cs = jwt.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380L * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getClaim("http://example.com/is_root"));
	}


	public void testExampleKristina()
		throws Exception {

		String jwtString = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=\n" +
			".eyJleHAiOjM3NzQ4NjQwNSwiYXpwIjoiRFAwMWd5M1Frd1ZHR2RJZWpJSmdMWEN0UlRnYSIsInN1\n" +
			"YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6IkRQMDFneTNRa3dWR0dkSWVqSUpnTFhDdFJU\n" +
			"Z2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMmVuZHBvaW50c1wvdG9r\n" +
			"ZW4iLCJpYXQiOjM3Mzg4NjQwNX0=\n" +
			".";

		PlainJWT plainJWT = PlainJWT.parse(jwtString);

		// Header
		assertEquals(Algorithm.NONE, plainJWT.getHeader().getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), plainJWT.getHeader().getType());

		// Claims
		assertEquals(new Date(377486405L * 1000), plainJWT.getJWTClaimsSet().getExpirationTime());
		assertEquals("DP01gy3QkwVGGdIejIJgLXCtRTga", plainJWT.getJWTClaimsSet().getClaim("azp"));
		assertEquals("admin@carbon.super", plainJWT.getJWTClaimsSet().getSubject());
		assertEquals("DP01gy3QkwVGGdIejIJgLXCtRTga", plainJWT.getJWTClaimsSet().getAudience().get(0));
		assertEquals("https://localhost:9443/oauth2endpoints/token", plainJWT.getJWTClaimsSet().getIssuer());
		assertEquals(new Date(373886405L * 1000), plainJWT.getJWTClaimsSet().getIssueTime());
	}
	
	
	public void testTrimWhitespace()
		throws Exception {
		
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().build());
		String jwtString = " " + jwt.serialize() + " ";
		PlainJWT.parse(jwtString);
	}
}
