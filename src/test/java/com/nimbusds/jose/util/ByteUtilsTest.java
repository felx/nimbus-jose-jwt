package com.nimbusds.jose.util;


import java.util.Arrays;

import junit.framework.TestCase;


/**
 * Tests the byte utilities.
 */
public class ByteUtilsTest extends TestCase {


	public void testGetBytesFromZeroInteger() {

		assertTrue(Arrays.equals(new byte[]{0, 0, 0, 0}, ByteUtils.getBytes(0)));
	}


	public void testGetBytesFromOneInteger() {

		assertTrue(Arrays.equals(new byte[]{0, 0, 0, 1}, ByteUtils.getBytes(1)));
	}
}
