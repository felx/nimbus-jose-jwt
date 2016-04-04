package com.nimbusds.jose.util;


import java.math.BigInteger;

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
