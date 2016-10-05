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

import com.nimbusds.jose.util.BigIntegerUtils;
import junit.framework.TestCase;


/**
 * Tests the big integer utility.
 *
 * @author Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest extends TestCase {


	public void testBigIntegerLeadingZeroPadding() {

		byte[] a1 = new BigInteger("123456789A", 16).toByteArray();
		byte[] a2 = new BigInteger("F23456789A", 16).toByteArray();

		assertEquals(a1.length + 1, a2.length);
		assertEquals(0, a2[0]);
	}


	public void testNoLeadingZero() {

		byte[] a1 = BigIntegerUtils.toBytesUnsigned(new BigInteger("123456789A", 16));
		byte[] a2 = BigIntegerUtils.toBytesUnsigned(new BigInteger("F23456789A", 16));

		assertEquals(a1.length, a2.length);
	}
}
