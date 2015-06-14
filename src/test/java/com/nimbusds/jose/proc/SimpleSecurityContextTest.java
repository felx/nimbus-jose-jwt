package com.nimbusds.jose.proc;


import java.util.Map;

import junit.framework.TestCase;


/**
 * Tests the map-based secruty context.
 *
 * @version 2015-06-14
 */
public class SimpleSecurityContextTest extends TestCase {


	public void testInstanceOfMap() {

		SimpleSecurityContext ctx = new SimpleSecurityContext();

		assertTrue(ctx instanceof Map);

		ctx.put("ip", "10.20.30.40");
		assertEquals("10.20.30.40", ctx.get("ip"));
	}
}
