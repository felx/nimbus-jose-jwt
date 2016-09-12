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

package com.nimbusds.jose.crypto;


import junit.framework.TestCase;


/**
 * Tests the array utilities.
 */
public class ConstantTimeUtilsTest extends TestCase {


	public void testConstantTimeEquality() {

		byte[] a = { 1, 2, 3, 4, 5, 6, 7, 8};
		byte[] b = { 1, 2, 3, 4, 5, 6, 7, 8};

		assertTrue(ConstantTimeUtils.areEqual(a, b));
	}


	public void testConstantTimeInequality() {

		byte[] a = { 1, 2, 3, 4, 5, 6, 7, 8};
		byte[] b = { 1, 2, 3, 4, 5, 6, 7, 7};

		assertFalse(ConstantTimeUtils.areEqual(a, b));
	}


	public void testConstantTimeLengthMismatch() {

		byte[] a = { 1, 2, 3, 4, 5, 6, 7, 8};
		byte[] b = { 1, 2, 3, 4, 5, 6, 7};

		assertFalse(ConstantTimeUtils.areEqual(a, b));
	}
}
