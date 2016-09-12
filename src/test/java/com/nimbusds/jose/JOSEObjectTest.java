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


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JOSE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-02-04
 */
public class JOSEObjectTest extends TestCase {
	
	
	public void testSplitThreeParts() {

		// Implies JWS
		String s = "abc.def.ghi";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals(3, parts.length);

		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}


	public void testSplitFiveParts() {

		// Implies JWE
		String s = "abc.def.ghi.jkl.mno";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals(5, parts.length);

		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
		assertEquals("jkl", parts[3].toString());
		assertEquals("mno", parts[4].toString());
	}


	public void testSplitEmptyThirdPart() {

		// Implies plain JOSE object
		String s = "abc.def.";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals(3, parts.length);

		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("", parts[2].toString());
	}


	public void testSplitEmptySecondPart() {

		// JWS with empty payload
		String s = "abc..ghi";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals(3, parts.length);

		assertEquals("abc", parts[0].toString());
		assertEquals("", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}


	public void testSplitEmptyFiveParts() {

		// JWS with empty payload
		String s = "....";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals(5, parts.length);

		assertEquals("", parts[0].toString());
		assertEquals("", parts[1].toString());
		assertEquals("", parts[2].toString());
		assertEquals("", parts[3].toString());
		assertEquals("", parts[4].toString());
	}


	public void testSplitException() {

		// Illegal JOSE
		String s = "abc.def";

		Base64URL[] parts = null;

		try {
			parts = JOSEObject.split(s);

			fail("Failed to raise exception");

		} catch (ParseException e) {

			// ok
		}
	}


	public void testMIMETypes() {

		assertEquals("application/jose; charset=UTF-8", JOSEObject.MIME_TYPE_COMPACT);
		assertEquals("application/jose+json; charset=UTF-8", JOSEObject.MIME_TYPE_JS);
	}
}
