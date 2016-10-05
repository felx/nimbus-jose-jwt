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
 * Tests the key length exception.
 */
public class KeyLengthExceptionTest extends TestCase {


	public void testMessageConstructor() {

		KeyLengthException e = new KeyLengthException("abc");

		assertEquals("abc", e.getMessage());
		assertEquals(0, e.getExpectedKeyLength());
		assertNull(e.getAlgorithm());
	}


	public void testDetailConstructor() {

		KeyLengthException e = new KeyLengthException(128, EncryptionMethod.A128GCM);

		assertEquals("The expected key length is 128 bits (for A128GCM algorithm)", e.getMessage());
		assertEquals(128, e.getExpectedKeyLength());
		assertEquals(EncryptionMethod.A128GCM, e.getAlgorithm());
	}
}
