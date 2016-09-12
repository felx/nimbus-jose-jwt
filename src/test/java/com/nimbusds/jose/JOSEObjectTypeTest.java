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

package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the JOSE object type header parmeter.
 */
public class JOSEObjectTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("JOSE", JOSEObjectType.JOSE.getType());
		assertEquals("JOSE+JSON", JOSEObjectType.JOSE_JSON.getType());
		assertEquals("JWT", JOSEObjectType.JWT.getType());
	}


	public void testToString() {

		assertEquals(JOSEObjectType.JOSE.getType(), JOSEObjectType.JOSE.toString());
		assertEquals(JOSEObjectType.JOSE_JSON.getType(), JOSEObjectType.JOSE_JSON.toString());
		assertEquals(JOSEObjectType.JWT.getType(), JOSEObjectType.JWT.toString());
	}


	public void testJSONAware() {

		assertEquals("\"JWT\"", JOSEObjectType.JWT.toJSONString());
	}
}
