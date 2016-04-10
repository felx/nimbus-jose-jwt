package com.nimbusds.jose.util;


import java.util.Arrays;

import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests the byte utilities.
 */
public class ByteUtilsTest extends TestCase {


	public void testConcat() {

		byte[] a1 = { (byte)1, (byte)2 };
		byte[] a2 = { (byte)3, (byte)4 };

		byte[] out = ByteUtils.concat(a1, a2);

		assertTrue(Arrays.equals(new byte[]{(byte)1, (byte)2, (byte)3, (byte)4}, out));
	}


	public void testConcatWithNullValue() {

		byte[] a1 = { (byte)1, (byte)2 };
		byte[] a2 = null;
		byte[] a3 = { (byte)3, (byte)4 };

		byte[] out = ByteUtils.concat(a1, a2, a3);

		assertTrue(Arrays.equals(new byte[]{(byte)1, (byte)2, (byte)3, (byte)4}, out));
	}
}
