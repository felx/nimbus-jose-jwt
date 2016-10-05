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
 * Tests the EncryptionMethod class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-10-14
 */
public class EncryptionMethodTest extends TestCase {


	public void testCMKLengths() {

		assertEquals(256, EncryptionMethod.A128CBC_HS256.cekBitLength());
		assertEquals(384, EncryptionMethod.A192CBC_HS384.cekBitLength());
		assertEquals(512, EncryptionMethod.A256CBC_HS512.cekBitLength());

		assertEquals(128, EncryptionMethod.A128GCM.cekBitLength());
		assertEquals(192, EncryptionMethod.A192GCM.cekBitLength());
		assertEquals(256, EncryptionMethod.A256GCM.cekBitLength());

		assertEquals(256, EncryptionMethod.A128CBC_HS256_DEPRECATED.cekBitLength());
		assertEquals(512, EncryptionMethod.A256CBC_HS512_DEPRECATED.cekBitLength());
	}


	public void testAESCBCHMACFamily() {

		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A256CBC_HS512));
		assertEquals(3, EncryptionMethod.Family.AES_CBC_HMAC_SHA.size());
	}


	public void testAESGCMFamily() {

		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A256GCM));
		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A192GCM));
		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A256GCM));
		assertEquals(3, EncryptionMethod.Family.AES_GCM.size());
	}
}
