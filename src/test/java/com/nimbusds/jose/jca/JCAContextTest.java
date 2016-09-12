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

package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Tests the simple JCA context.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-08
 */
public class JCAContextTest extends TestCase {


	public void testDefaultConstructor() {

		JCAContext context = new JCAContext();
		assertNull(context.getProvider());
		assertNotNull(context.getSecureRandom());
	}


	public void testConstructor() {

		Provider provider = new Provider("general", 1.0, "test") {};
		SecureRandom sr = new SecureRandom();

		JCAContext context = new JCAContext(provider, sr);

		assertEquals(provider, context.getProvider());
		assertEquals(sr, context.getSecureRandom());
	}


	public void testSetters() {

		JCAContext context = new JCAContext();

		context.setProvider(new Provider("general", 1.0, "test") {
		});
		assertEquals("general", context.getProvider().getName());

		SecureRandom sr = new SecureRandom();
		context.setSecureRandom(sr);
		assertEquals(sr, context.getSecureRandom());
	}
}
