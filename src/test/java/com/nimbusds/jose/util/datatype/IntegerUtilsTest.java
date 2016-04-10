package com.nimbusds.jose.util.datatype;


import java.util.Arrays;

import junit.framework.TestCase;


/**
 * Tests the integer utilities.
 */
public class IntegerUtilsTest extends TestCase {


	public void testGetBytesFromZeroInteger() {

		assertTrue(Arrays.equals(new byte[]{0, 0, 0, 0}, IntegerUtils.toBytes(0)));
	}


	public void testGetBytesFromOneInteger() {

		assertTrue(Arrays.equals(new byte[]{0, 0, 0, 1}, IntegerUtils.toBytes(1)));
	}
}
