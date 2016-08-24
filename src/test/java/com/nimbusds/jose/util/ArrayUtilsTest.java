package com.nimbusds.jose.util;


import java.util.Arrays;

import junit.framework.TestCase;


public class ArrayUtilsTest extends TestCase {
	

	public void testConcat() {
		
		String[] out = ArrayUtils.concat(new String[]{"a", "b", "c"}, new String[]{"d", "e"});
		
		assertTrue(Arrays.equals(new String[]{"a", "b", "c", "d", "e"}, out));
	}
}
