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

package com.nimbusds.jose.jwk;


import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;


/**
 * Tests the key operation enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-04-03
 */
public class KeyOperationTest extends TestCase {


	public void testIdentifiers() {

		assertEquals("sign", KeyOperation.SIGN.identifier());
		assertEquals("sign", KeyOperation.SIGN.toString());

		assertEquals("verify", KeyOperation.VERIFY.identifier());
		assertEquals("verify", KeyOperation.VERIFY.toString());

		assertEquals("encrypt", KeyOperation.ENCRYPT.identifier());
		assertEquals("encrypt", KeyOperation.ENCRYPT.toString());

		assertEquals("decrypt", KeyOperation.DECRYPT.identifier());
		assertEquals("decrypt", KeyOperation.DECRYPT.toString());

		assertEquals("wrapKey", KeyOperation.WRAP_KEY.identifier());
		assertEquals("wrapKey", KeyOperation.WRAP_KEY.toString());

		assertEquals("unwrapKey", KeyOperation.UNWRAP_KEY.identifier());
		assertEquals("unwrapKey", KeyOperation.UNWRAP_KEY.toString());

		assertEquals("deriveKey", KeyOperation.DERIVE_KEY.identifier());
		assertEquals("deriveKey", KeyOperation.DERIVE_KEY.toString());

		assertEquals("deriveBits", KeyOperation.DERIVE_BITS.identifier());
		assertEquals("deriveBits", KeyOperation.DERIVE_BITS.toString());
	}


	public void testParseNull()
		throws ParseException {

		assertNull(KeyOperation.parse(null));
	}


	public void testParseSparseList()
		throws ParseException {

		List<String> sl = Arrays.asList("sign", null, "verify");

		Set<KeyOperation> ops = KeyOperation.parse(sl);
		assertTrue(ops.contains(KeyOperation.SIGN));
		assertTrue(ops.contains(KeyOperation.VERIFY));
		assertEquals(2, ops.size());
	}


	public void testParseList()
		throws ParseException {

		List<String> sl = Arrays.asList("sign", "verify");

		Set<KeyOperation> ops = KeyOperation.parse(sl);
		assertTrue(ops.contains(KeyOperation.SIGN));
		assertTrue(ops.contains(KeyOperation.VERIFY));
		assertEquals(2, ops.size());
	}


	public void testParseException() {

		List<String> sl = Arrays.asList("sign", "no-such-op", "verify");

		try {
			KeyOperation.parse(sl);
			fail();
		} catch (ParseException e) {
			// ok
		}
	}
}
