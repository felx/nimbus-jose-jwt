package com.nimbusds.jose;


import java.net.URL;
import java.util.*;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import junit.framework.TestCase;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-19)
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
		assertNull(h.getCriticalHeaders());
		assertNull(h.getEphemeralPublicKey());
		assertNull(h.getCompressionAlgorithm());
		assertNull(h.getAgreementPartyUInfo());
		assertNull(h.getAgreementPartyVInfo());
		assertNull(h.getPBES2Salt());
		assertNull(h.getIV());
		assertNull(h.getAuthenticationTag());
		assertEquals(0, h.getPBES2Count());
		assertTrue(h.getCustomParameters().isEmpty());
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

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("enc"));
		assertEquals(2, h.getIncludedParameters().size());
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

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("enc"));
		assertEquals(2, h.getIncludedParameters().size());
	}


	public void testSerializeAndParse()
		throws Exception {

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final KeyUse use = KeyUse.ENCRYPTION;
		final String kid = "1234";

		RSAKey jwk = new RSAKey(mod, exp, use, null, JWEAlgorithm.RSA1_5, kid, null, null, null);

		List<Base64> certChain = new LinkedList<>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM).
			type(new JOSEObjectType("JWT")).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			jwkURL(new URL("https://example.com/jku.json")).
			jwk(jwk).
			x509CertURL(new URL("https://example/cert.b64")).
			x509CertThumbprint(new Base64URL("789iop")).
			x509CertSHA256Thumbprint(new Base64URL("789asd")).
			x509CertChain(certChain).
			keyID("1234").
			agreementPartyUInfo(new Base64URL("abc")).
			agreementPartyVInfo(new Base64URL("xyz")).
			pbes2Salt(new Base64URL("omg")).
			pbes2Count(1000).
			iv(new Base64URL("101010")).
			tag(new Base64URL("202020")).
			customParameter("xCustom", "+++").
			build();


		Base64URL base64URL = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(base64URL);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URL("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URL("https://example/cert.b64"), h.getX509CertURL());
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
		assertEquals(new Base64URL("202020"), h.getAuthenticationTag());

		assertEquals("+++", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());

		assertEquals(base64URL, h.getParsedBase64URL());

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("enc"));
		assertTrue(h.getIncludedParameters().contains("zip"));
		assertTrue(h.getIncludedParameters().contains("jku"));
		assertTrue(h.getIncludedParameters().contains("jwk"));
		assertTrue(h.getIncludedParameters().contains("kid"));
		assertTrue(h.getIncludedParameters().contains("x5u"));
		assertTrue(h.getIncludedParameters().contains("x5t"));
		assertTrue(h.getIncludedParameters().contains("x5c"));
		assertTrue(h.getIncludedParameters().contains("apu"));
		assertTrue(h.getIncludedParameters().contains("apv"));
		assertTrue(h.getIncludedParameters().contains("p2s"));
		assertTrue(h.getIncludedParameters().contains("p2c"));
		assertTrue(h.getIncludedParameters().contains("iv"));
		assertTrue(h.getIncludedParameters().contains("tag"));
		assertTrue(h.getIncludedParameters().contains("xCustom"));
		assertEquals(18, h.getIncludedParameters().size());

		// Test copy constructor
		h = new JWEHeader(h);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URL("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URL("https://example/cert.b64"), h.getX509CertURL());
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
		assertEquals(new Base64URL("202020"), h.getAuthenticationTag());

		assertEquals("+++", (String)h.getCustomParameter("xCustom"));
		assertEquals(1, h.getCustomParameters().size());

		assertEquals(base64URL, h.getParsedBase64URL());
	}


	public void testCrit()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			criticalHeaders(crit).
			build();

		assertEquals(3, h.getCriticalHeaders().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(b64url);
		
		crit = h.getCriticalHeaders();

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
			type(JOSEObjectType.JWS).
			contentType("application/json").
			criticalHeaders(new HashSet<>(Arrays.asList("exp", "nbf"))).
			jwkURL(new URL("http://example.com/jwk.json")).
			jwk(new OctetSequenceKey.Builder(new Base64URL("xyz")).build()).
			x509CertURL(new URL("http://example.com/cert.pem")).
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
			tag(new Base64URL("202020")).
			customParameter("exp", 123).
			customParameter("nbf", 456).
			build();

		assertEquals(JWEAlgorithm.A128KW, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, h.getEncryptionMethod());
		assertEquals(JOSEObjectType.JWS, h.getType());
		assertEquals("application/json", h.getContentType());
		assertTrue(h.getCriticalHeaders().contains("exp"));
		assertTrue(h.getCriticalHeaders().contains("nbf"));
		assertEquals(2, h.getCriticalHeaders().size());
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
		assertEquals("202020", h.getAuthenticationTag().toString());
		assertEquals(123, ((Integer)h.getCustomParameter("exp")).intValue());
		assertEquals(456, ((Integer)h.getCustomParameter("nbf")).intValue());
		assertEquals(2, h.getCustomParameters().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("enc"));
		assertTrue(h.getIncludedParameters().contains("typ"));
		assertTrue(h.getIncludedParameters().contains("cty"));
		assertTrue(h.getIncludedParameters().contains("crit"));
		assertTrue(h.getIncludedParameters().contains("jku"));
		assertTrue(h.getIncludedParameters().contains("jwk"));
		assertTrue(h.getIncludedParameters().contains("x5u"));
		assertTrue(h.getIncludedParameters().contains("x5t"));
		assertTrue(h.getIncludedParameters().contains("x5t#S256"));
		assertTrue(h.getIncludedParameters().contains("x5c"));
		assertTrue(h.getIncludedParameters().contains("kid"));
		assertTrue(h.getIncludedParameters().contains("zip"));
		assertTrue(h.getIncludedParameters().contains("apu"));
		assertTrue(h.getIncludedParameters().contains("apv"));
		assertTrue(h.getIncludedParameters().contains("p2s"));
		assertTrue(h.getIncludedParameters().contains("p2c"));
		assertTrue(h.getIncludedParameters().contains("iv"));
		assertTrue(h.getIncludedParameters().contains("tag"));
		assertTrue(h.getIncludedParameters().contains("exp"));
		assertTrue(h.getIncludedParameters().contains("nbf"));
		assertEquals(21, h.getIncludedParameters().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
			customParameters(customParams).
			build();

		assertEquals("1", (String)h.getCustomParameter("x"));
		assertEquals("2", (String)h.getCustomParameter("y"));
		assertEquals(2, h.getCustomParameters().size());
	}
}
