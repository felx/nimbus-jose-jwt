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

package com.nimbusds.jose.jwk;


import java.io.File;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import junit.framework.TestCase;


/**
 * Tests the base JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-07
 */
public class JWKTest extends TestCase {

	public void testMIMEType() {

		assertEquals("application/jwk+json; charset=UTF-8", JWK.MIME_TYPE);
	}
	
	
	public void testParseRSAJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		assertEquals(KeyType.RSA, jwk.getKeyType());
		assertNull(jwk.getAlgorithm());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertNull(jwk.getKeyOperations());
		assertEquals(1, jwk.getX509CertChain().size());
		assertNotNull(jwk.getX509CertThumbprint());
		assertFalse(jwk.isPrivate());
		assertTrue(jwk instanceof RSAKey);
	}
	
	
	public void testParseECJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		assertEquals(KeyType.EC, jwk.getKeyType());
		assertNull(jwk.getAlgorithm());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertNull(jwk.getKeyOperations());
		assertEquals(1, jwk.getX509CertChain().size());
		assertNotNull(jwk.getX509CertThumbprint());
		assertFalse(jwk.isPrivate());
		assertTrue(jwk instanceof ECKey);
		assertEquals(ECKey.Curve.P_256, ((ECKey)jwk).getCurve());
	}
}
