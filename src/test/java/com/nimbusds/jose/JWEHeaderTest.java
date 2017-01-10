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


import java.net.URI;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-01-10
 */
public class JWEHeaderTest extends TestCase {


	public void testMinimalConstructor() {

		JWEHeader h = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

		assertEquals(JWEAlgorithm.A128KW, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, h.getEncryptionMethod());
		assertNull(h.getJWKURL());
		assertNull(h.getJWK());
		assertNull(h.getX509CertURL());
		assertNull(h.getX509CertThumbprint());
		assertNull(h.getX509CertSHA256Thumbprint());
		assertNull(h.getX509CertChain());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertNull(h.getEphemeralPublicKey());
		assertNull(h.getCompressionAlgorithm());
		assertNull(h.getAgreementPartyUInfo());
		assertNull(h.getAgreementPartyVInfo());
		assertNull(h.getPBES2Salt());
		assertNull(h.getIV());
		assertNull(h.getAuthTag());
		assertEquals(0, h.getPBES2Count());
		assertTrue(h.getCustomParams().isEmpty());
	}


	public void testParse1()
		throws Exception {

		// Example header from JWE spec
		// {"alg":"RSA-OAEP","enc":"A256GCM"}
		Base64URL in = new Base64URL("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ");

		JWEHeader h = JWEHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertNotNull(h);

		assertEquals(JWEAlgorithm.RSA_OAEP, h.getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());

		assertNull(h.getType());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("enc"));
		assertEquals(2, h.getIncludedParams().size());
	}


	public void testParse2()
		throws Exception {

		// Example header from JWE spec
		// {"alg":"RSA1_5","enc":"A128CBC-HS256"}
		Base64URL in = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

		JWEHeader h = JWEHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertNotNull(h);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, h.getEncryptionMethod());

		assertNull(h.getType());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("enc"));
		assertEquals(2, h.getIncludedParams().size());
	}


	public void testSerializeAndParse()
		throws Exception {

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final KeyUse use = KeyUse.ENCRYPTION;
		final String kid = "1234";

		RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA1_5).keyID(kid).build();

		List<Base64> certChain = new LinkedList<>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM).
			type(new JOSEObjectType("JWT")).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			jwkURL(new URI("https://example.com/jku.json")).
			jwk(jwk).
			x509CertURL(new URI("https://example/cert.b64")).
			x509CertThumbprint(new Base64URL("789iop")).
			x509CertSHA256Thumbprint(new Base64URL("789asd")).
			x509CertChain(certChain).
			keyID("1234").
			agreementPartyUInfo(new Base64URL("abc")).
			agreementPartyVInfo(new Base64URL("xyz")).
			pbes2Salt(new Base64URL("omg")).
			pbes2Count(1000).
			iv(new Base64URL("101010")).
			authTag(new Base64URL("202020")).
			customParam("xCustom", "+++").
			build();


		Base64URL base64URL = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(base64URL);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals(new Base64URL("abc"), h.getAgreementPartyUInfo());
		assertEquals(new Base64URL("xyz"), h.getAgreementPartyVInfo());

		assertEquals(new Base64URL("omg"), h.getPBES2Salt());
		assertEquals(1000, h.getPBES2Count());

		assertEquals(new Base64URL("101010"), h.getIV());
		assertEquals(new Base64URL("202020"), h.getAuthTag());

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("enc"));
		assertTrue(h.getIncludedParams().contains("zip"));
		assertTrue(h.getIncludedParams().contains("jku"));
		assertTrue(h.getIncludedParams().contains("jwk"));
		assertTrue(h.getIncludedParams().contains("kid"));
		assertTrue(h.getIncludedParams().contains("x5u"));
		assertTrue(h.getIncludedParams().contains("x5t"));
		assertTrue(h.getIncludedParams().contains("x5c"));
		assertTrue(h.getIncludedParams().contains("apu"));
		assertTrue(h.getIncludedParams().contains("apv"));
		assertTrue(h.getIncludedParams().contains("p2s"));
		assertTrue(h.getIncludedParams().contains("p2c"));
		assertTrue(h.getIncludedParams().contains("iv"));
		assertTrue(h.getIncludedParams().contains("tag"));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(18, h.getIncludedParams().size());

		// Test copy constructor
		h = new JWEHeader(h);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals(new Base64URL("abc"), h.getAgreementPartyUInfo());
		assertEquals(new Base64URL("xyz"), h.getAgreementPartyVInfo());

		assertEquals(new Base64URL("omg"), h.getPBES2Salt());
		assertEquals(1000, h.getPBES2Count());

		assertEquals(new Base64URL("101010"), h.getIV());
		assertEquals(new Base64URL("202020"), h.getAuthTag());

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());
	}


	public void testCrit()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			criticalParams(crit).
			build();

		assertEquals(3, h.getCriticalParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(b64url);
		
		crit = h.getCriticalParams();

		assertTrue(crit.contains("iat"));
		assertTrue(crit.contains("exp"));
		assertTrue(crit.contains("nbf"));

		assertEquals(3, crit.size());
	}


	public void testRejectNone() {

		try {
			new JWEHeader(new JWEAlgorithm("none"), EncryptionMethod.A128CBC_HS256);

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testBuilder()
		throws Exception {

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
			type(JOSEObjectType.JOSE).
			contentType("application/json").
			criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
			jwkURL(new URI("http://example.com/jwk.json")).
			jwk(new OctetSequenceKey.Builder(new Base64URL("xyz")).build()).
			x509CertURL(new URI("http://example.com/cert.pem")).
			x509CertThumbprint(new Base64URL("abc")).
			x509CertSHA256Thumbprint(new Base64URL("abc256")).
			x509CertChain(Arrays.asList(new Base64("abc"), new Base64("def"))).
			keyID("123").
			compressionAlgorithm(CompressionAlgorithm.DEF).
			agreementPartyUInfo(new Base64URL("qwe")).
			agreementPartyVInfo(new Base64URL("rty")).
			pbes2Salt(new Base64URL("uiop")).
			pbes2Count(1000).
			iv(new Base64URL("101010")).
			authTag(new Base64URL("202020")).
			customParam("exp", 123).
			customParam("nbf", 456).
			build();

		assertEquals(JWEAlgorithm.A128KW, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, h.getEncryptionMethod());
		assertEquals(JOSEObjectType.JOSE, h.getType());
		assertEquals("application/json", h.getContentType());
		assertTrue(h.getCriticalParams().contains("exp"));
		assertTrue(h.getCriticalParams().contains("nbf"));
		assertEquals(2, h.getCriticalParams().size());
		assertEquals("http://example.com/jwk.json", h.getJWKURL().toString());
		assertEquals("xyz", ((OctetSequenceKey)h.getJWK()).getKeyValue().toString());
		assertEquals("http://example.com/cert.pem", h.getX509CertURL().toString());
		assertEquals("abc", h.getX509CertThumbprint().toString());
		assertEquals("abc256", h.getX509CertSHA256Thumbprint().toString());
		assertEquals("abc", h.getX509CertChain().get(0).toString());
		assertEquals("def", h.getX509CertChain().get(1).toString());
		assertEquals(2, h.getX509CertChain().size());
		assertEquals("123", h.getKeyID());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals("qwe", h.getAgreementPartyUInfo().toString());
		assertEquals("rty", h.getAgreementPartyVInfo().toString());
		assertEquals("uiop", h.getPBES2Salt().toString());
		assertEquals(1000, h.getPBES2Count());
		assertEquals("101010", h.getIV().toString());
		assertEquals("202020", h.getAuthTag().toString());
		assertEquals(123, ((Integer)h.getCustomParam("exp")).intValue());
		assertEquals(456, ((Integer)h.getCustomParam("nbf")).intValue());
		assertEquals(2, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("enc"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("cty"));
		assertTrue(h.getIncludedParams().contains("crit"));
		assertTrue(h.getIncludedParams().contains("jku"));
		assertTrue(h.getIncludedParams().contains("jwk"));
		assertTrue(h.getIncludedParams().contains("x5u"));
		assertTrue(h.getIncludedParams().contains("x5t"));
		assertTrue(h.getIncludedParams().contains("x5t#S256"));
		assertTrue(h.getIncludedParams().contains("x5c"));
		assertTrue(h.getIncludedParams().contains("kid"));
		assertTrue(h.getIncludedParams().contains("zip"));
		assertTrue(h.getIncludedParams().contains("apu"));
		assertTrue(h.getIncludedParams().contains("apv"));
		assertTrue(h.getIncludedParams().contains("p2s"));
		assertTrue(h.getIncludedParams().contains("p2c"));
		assertTrue(h.getIncludedParams().contains("iv"));
		assertTrue(h.getIncludedParams().contains("tag"));
		assertTrue(h.getIncludedParams().contains("exp"));
		assertTrue(h.getIncludedParams().contains("nbf"));
		assertEquals(21, h.getIncludedParams().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
	}
}
