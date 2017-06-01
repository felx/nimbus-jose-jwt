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


import java.nio.charset.Charset;
import java.util.Arrays;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.IntegerOverflowException;
import junit.framework.TestCase;


/**
 * Tests the Additional Authenticated Data (AAD) functions.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-06-01
 */
public class AADTest extends TestCase {


	public void testComputeForJWEHeader() {

		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		byte[] expected = jweHeader.toBase64URL().toString().getBytes(Charset.forName("ASCII"));

		assertTrue(Arrays.equals(expected, AAD.compute(jweHeader)));
	}


	public void testComputeForBase64URL() {

		Base64URL base64URL = Base64URL.encode("Hello world!");

		byte[] expected = base64URL.toString().getBytes(Charset.forName("ASCII"));

		assertTrue(Arrays.equals(expected, AAD.compute(base64URL)));
	}


	public void testComputeLength()
		throws IntegerOverflowException {

		byte[] aad = new byte[]{0, 1, 2, 3}; // 32 bits

		byte[] expectedBitLength = new byte[]{0, 0, 0, 0, 0, 0, 0, 32};

		assertTrue(Arrays.equals(expectedBitLength, AAD.computeLength(aad)));
	}
}
