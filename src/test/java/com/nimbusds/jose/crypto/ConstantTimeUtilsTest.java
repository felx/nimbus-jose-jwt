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
