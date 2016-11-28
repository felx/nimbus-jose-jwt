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


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Tests JWE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-08-20
 */
public class JWEObjectTest extends TestCase {


	public void testBase64URLConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, 
			                         EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jwe = new JWEObject(firstPart, secondPart,
				thirdPart, fourthPart, 
				fifthPart);

		assertEquals(firstPart, jwe.getHeader().toBase64URL());
		assertEquals(secondPart, jwe.getEncryptedKey());
		assertEquals(thirdPart, jwe.getIV());
		assertEquals(fourthPart, jwe.getCipherText());

		assertEquals(firstPart.toString() + ".abc.def.ghi.jkl", jwe.serialize());
		assertEquals(firstPart.toString() + ".abc.def.ghi.jkl", jwe.getParsedString());

		assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
	}


	public void testRejectUnsupportedJWEAlgorithmOnEncrypt()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(new JWEAlgorithm("xyz"));
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return null;
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The \"RSA1_5\" algorithm is not supported by the JWE encrypter: Supported algorithms: [xyz]", e.getMessage());
		}
	}


	public void testRejectUnsupportedJWEMethodOnEncrypt()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(JWEAlgorithm.RSA1_5);
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return Collections.singleton(new EncryptionMethod("xyz"));
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The \"A128CBC-HS256\" encryption method or key size is not supported by the JWE encrypter: Supported methods: [xyz]", e.getMessage());
		}
	}
}
