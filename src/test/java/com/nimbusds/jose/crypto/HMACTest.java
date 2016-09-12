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

package com.nimbusds.jose.crypto;


import java.security.Provider;
import javax.crypto.Mac;

import org.junit.Assert;
import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the HMAC helper class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-01-28
 */
public class HMACTest extends TestCase {


	public void testVector()
		throws Exception {

		// Vectors from http://openidtest.uninett.no/jwt#

		byte[] msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUub3JnIiwidHlwIjoiSldUIn0".getBytes("UTF-8");
		byte[] mac = new Base64URL("eagkgLML8Ccrn4eIvidX4a10JBE4Q3eaOAf4Blj9P4c").decode();
		byte[] key = "1879197b29d8ec57".getBytes("UTF-8");

		final Provider provider = null;
		byte[] computedMac = HMAC.compute("HMACSHA256", key, msg, provider);

		assertEquals(computedMac.length, mac.length);
		Assert.assertArrayEquals(mac, computedMac);
	}


	public void testVectorWithExplicitProvider()
		throws Exception {

		// Vectors from http://openidtest.uninett.no/jwt#

		byte[] msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUub3JnIiwidHlwIjoiSldUIn0".getBytes("UTF-8");
		byte[] mac = new Base64URL("eagkgLML8Ccrn4eIvidX4a10JBE4Q3eaOAf4Blj9P4c").decode();
		byte[] key = "1879197b29d8ec57".getBytes("UTF-8");

		final Provider provider =Mac.getInstance("HMACSHA256").getProvider();
		byte[] computedMac = HMAC.compute("HMACSHA256", key, msg, provider);

		assertEquals(computedMac.length, mac.length);
		Assert.assertArrayEquals(mac, computedMac);
	}
}
