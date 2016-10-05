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
