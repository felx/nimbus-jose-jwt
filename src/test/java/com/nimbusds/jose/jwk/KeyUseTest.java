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
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.text.ParseException;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import junit.framework.TestCase;


/**
 * Tests the key use enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-06
 */
public class KeyUseTest extends TestCase {


	public void testIdentifiers() {

		assertEquals("sig", KeyUse.SIGNATURE.identifier());
		assertEquals("sig", KeyUse.SIGNATURE.toString());

		assertEquals("enc", KeyUse.ENCRYPTION.identifier());
		assertEquals("enc", KeyUse.ENCRYPTION.toString());
	}


	public void testParse()
		throws ParseException {

		assertEquals(KeyUse.SIGNATURE, KeyUse.parse("sig"));
		assertEquals(KeyUse.ENCRYPTION, KeyUse.parse("enc"));
	}


	public void testParseException() {

		try {
			KeyUse.parse("no-such-use");

			fail();

		} catch (ParseException e) {
			// ok
		}
	}


	public void testParseNull()
		throws ParseException {

		assertNull(KeyUse.parse(null));
	}
	
	
	public void testInferKeyUseFromX509Cert_RSAENC()
		throws IOException {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
		assertEquals(KeyUse.ENCRYPTION, KeyUse.from(x509Cert));
	}
	
	
	public void testInferKeyUseFromX509Cert_ECDH()
		throws IOException {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
		assertEquals(KeyUse.ENCRYPTION, KeyUse.from(x509Cert));
	}
}
