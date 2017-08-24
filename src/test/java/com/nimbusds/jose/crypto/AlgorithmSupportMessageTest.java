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


import java.util.Collection;
import java.util.LinkedHashSet;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import junit.framework.TestCase;


/**
 * Tests the algorithm support utility.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-20
 */
public class AlgorithmSupportMessageTest extends TestCase {


	public void testWithJWSAlgorithm() {

		JWSAlgorithm unsupported = JWSAlgorithm.ES256;

		Collection<JWSAlgorithm> supported = new LinkedHashSet<>();
		supported.add(JWSAlgorithm.HS256);

		String msg = AlgorithmSupportMessage.unsupportedJWSAlgorithm(unsupported, supported);

		assertEquals("Unsupported JWS algorithm ES256, must be HS256", msg);
	}


	public void testWithJWEAlgorithm() {

		JWEAlgorithm unsupported = JWEAlgorithm.A128GCMKW;

		Collection<JWEAlgorithm> supported = new LinkedHashSet<>();
		supported.add(JWEAlgorithm.RSA1_5);
		supported.add(JWEAlgorithm.RSA_OAEP);

		String msg = AlgorithmSupportMessage.unsupportedJWEAlgorithm(unsupported, supported);

		assertEquals("Unsupported JWE algorithm A128GCMKW, must be RSA1_5 or RSA-OAEP", msg);
	}


	public void testWithEncryptionMethod() {

		EncryptionMethod unsupported = EncryptionMethod.A128CBC_HS256_DEPRECATED;

		Collection<EncryptionMethod> supported = new LinkedHashSet<>();
		supported.add(EncryptionMethod.A128GCM);
		supported.add(EncryptionMethod.A192GCM);
		supported.add(EncryptionMethod.A256GCM);

		String msg = AlgorithmSupportMessage.unsupportedEncryptionMethod(unsupported, supported);

		assertEquals("Unsupported JWE encryption method A128CBC+HS256, must be A128GCM, A192GCM or A256GCM", msg);
	}


	public void testWithEllipticCurve() {

		Curve unsupported = new Curve("P-986");

		Collection<Curve> supported = new LinkedHashSet<>();
		supported.add(Curve.P_256);
		supported.add(Curve.P_384);
		supported.add(Curve.P_521);

		String msg = AlgorithmSupportMessage.unsupportedEllipticCurve(unsupported, supported);

		assertEquals("Unsupported elliptic curve P-986, must be P-256, P-384 or P-521", msg);
	}
}
