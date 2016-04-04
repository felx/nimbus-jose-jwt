package com.nimbusds.jose.util;


import junit.framework.TestCase;


/**
 * Tests the JSON object utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-03-16
 */
public class JSONObjectUtilsTest extends TestCase {


	public void testParseTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONObjectUtils.parseJSONObject("{} ").size());
		assertEquals(0, JSONObjectUtils.parseJSONObject("{}\n").size());
		assertEquals(0, JSONObjectUtils.parseJSONObject("{}\r\n").size());
	}
}
