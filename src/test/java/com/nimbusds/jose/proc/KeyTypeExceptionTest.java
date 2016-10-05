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


import junit.framework.TestCase;

import com.nimbusds.jose.KeyTypeException;


/**
 * Key type exception test.
 */
public class KeyTypeExceptionTest extends TestCase {


	public void testMessage() {

		KeyTypeException e = new KeyTypeException(java.security.interfaces.RSAPublicKey.class);

		assertEquals("Invalid key: Must be an instance of interface java.security.interfaces.RSAPublicKey", e.getMessage());
	}
}
