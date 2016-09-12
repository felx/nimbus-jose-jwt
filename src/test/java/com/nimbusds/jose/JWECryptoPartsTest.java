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

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the JWE crypto parts class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-11
 */
public class JWECryptoPartsTest extends TestCase {


	public void testConstructorWithoutHeader() {

		JWECryptoParts p = new JWECryptoParts(
			new Base64URL("abc"),
			new Base64URL("def"),
			new Base64URL("ghi"),
			new Base64URL("jkl")
		);


		assertNull(p.getHeader());
		assertEquals("abc", p.getEncryptedKey().toString());
		assertEquals("def", p.getInitializationVector().toString());
		assertEquals("ghi", p.getCipherText().toString());
		assertEquals("jkl", p.getAuthenticationTag().toString());


		p = new JWECryptoParts(null, null, new Base64URL("abc"), null);

		assertNull(p.getHeader());
		assertNull(p.getEncryptedKey());
		assertNull(p.getInitializationVector());
		assertEquals("abc", p.getCipherText().toString());
		assertNull(p.getAuthenticationTag());
	}


	public void testConstructorWithHeader() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

		JWECryptoParts p = new JWECryptoParts(
			header,
			new Base64URL("abc"),
			new Base64URL("def"),
			new Base64URL("ghi"),
			new Base64URL("jkl")
		);

		assertEquals(header, p.getHeader());
		assertEquals("abc", p.getEncryptedKey().toString());
		assertEquals("def", p.getInitializationVector().toString());
		assertEquals("ghi", p.getCipherText().toString());
		assertEquals("jkl", p.getAuthenticationTag().toString());

		p = new JWECryptoParts(null, null, null, new Base64URL("abc"), null);

		assertNull(p.getHeader());
		assertNull(p.getEncryptedKey());
		assertNull(p.getInitializationVector());
		assertEquals("abc", p.getCipherText().toString());
		assertNull(p.getAuthenticationTag());
	}
}
