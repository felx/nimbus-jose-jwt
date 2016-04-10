package com.nimbusds.jose.util.json;


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

		assertEquals(0, JSONObjectUtils.parse("{} ").size());
		assertEquals(0, JSONObjectUtils.parse("{}\n").size());
		assertEquals(0, JSONObjectUtils.parse("{}\r\n").size());
	}
}
