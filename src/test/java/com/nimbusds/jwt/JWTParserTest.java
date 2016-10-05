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

package com.nimbusds.jwt;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;


/**
 * Tests the JWT parser. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-19
 */
public class JWTParserTest extends TestCase {


	public void testParsePlainJWT()
		throws Exception {

		String s = "eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".";

		JWT jwt = JWTParser.parse(s);

		assertEquals(Algorithm.NONE, jwt.getHeader().getAlgorithm());
		
		assertTrue(jwt instanceof PlainJWT);
		
		PlainJWT plainJWT = (PlainJWT)jwt;

		assertEquals(Algorithm.NONE, plainJWT.getHeader().getAlgorithm());
		assertNull(plainJWT.getHeader().getType());
		assertNull(plainJWT.getHeader().getContentType());

		JWTClaimsSet cs = plainJWT.getJWTClaimsSet();

		assertEquals("joe", cs.getIssuer());
		assertEquals(new Date(1300819380L * 1000), cs.getExpirationTime());
		assertTrue((Boolean)cs.getClaim("http://example.com/is_root"));
	}
	
	
	public void testParseEncryptedJWT()
		throws Exception {
		
		String s = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
			"QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" +
			"oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" +
			"TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" +
			"sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" +
			"YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" +
			"1rZgN5TiysnmzTROF869lQ." +
			"AxY8DCtDaGlsbGljb3RoZQ." +
			"MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" +
			"HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." +
			"fiK51VwhsxJ-siBMR-YFiA";
		
		JWT jwt = JWTParser.parse(s);

		assertEquals(JWEAlgorithm.RSA1_5, jwt.getHeader().getAlgorithm());
		
		assertTrue(jwt instanceof EncryptedJWT);
		
		EncryptedJWT encryptedJWT = (EncryptedJWT)jwt;
		
		assertEquals(JWEObject.State.ENCRYPTED, encryptedJWT.getState());
		
		assertEquals(JWEAlgorithm.RSA1_5, encryptedJWT.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, encryptedJWT.getHeader().getEncryptionMethod());
		assertNull(encryptedJWT.getHeader().getType());
		assertNull(encryptedJWT.getHeader().getContentType());
	}
}
