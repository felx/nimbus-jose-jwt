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

package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the JWS Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-08-24
 */
public class JWSAlgorithmTest extends TestCase {


	public void testParse() {

		assertEquals(JWSAlgorithm.HS256, JWSAlgorithm.parse("HS256"));
		assertEquals(JWSAlgorithm.HS384, JWSAlgorithm.parse("HS384"));
		assertEquals(JWSAlgorithm.HS512, JWSAlgorithm.parse("HS512"));

		assertEquals(JWSAlgorithm.RS256, JWSAlgorithm.parse("RS256"));
		assertEquals(JWSAlgorithm.RS384, JWSAlgorithm.parse("RS384"));
		assertEquals(JWSAlgorithm.RS512, JWSAlgorithm.parse("RS512"));

		assertEquals(JWSAlgorithm.ES256, JWSAlgorithm.parse("ES256"));
		assertEquals(JWSAlgorithm.ES384, JWSAlgorithm.parse("ES384"));
		assertEquals(JWSAlgorithm.ES512, JWSAlgorithm.parse("ES512"));

		assertEquals(JWSAlgorithm.PS256, JWSAlgorithm.parse("PS256"));
		assertEquals(JWSAlgorithm.PS384, JWSAlgorithm.parse("PS384"));
		assertEquals(JWSAlgorithm.PS512, JWSAlgorithm.parse("PS512"));
	}


	public void testHMACFamily() {

		assertTrue(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS256));
		assertTrue(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS384));
		assertTrue(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS512));
		assertEquals(3, JWSAlgorithm.Family.HMAC_SHA.size());
	}


	public void testRSAFamily() {

		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS256));
		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS384));
		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS512));
		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS256));
		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS384));
		assertTrue(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS512));
		assertEquals(6, JWSAlgorithm.Family.RSA.size());
	}


	public void testECFamily() {

		assertTrue(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES256));
		assertTrue(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES384));
		assertTrue(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES512));
		assertEquals(3, JWSAlgorithm.Family.EC.size());
	}
	
	
	public void testSignatureSuperFamily() {
		
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS512));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS512));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES512));
		assertEquals(9, JWSAlgorithm.Family.SIGNATURE.size());
	}
}
