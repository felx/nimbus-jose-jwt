package com.nimbusds.jose;


import java.net.URL;
import java.text.ParseException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.Use;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-30)
 */
public class JWEHeaderTest extends TestCase {


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

		JWEHeader h = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM);

		h.setType(new JOSEObjectType("JWT"));
		h.setCompressionAlgorithm(CompressionAlgorithm.DEF);
		h.setJWKURL(new URL("https://example.com/jku.json"));
		h.setKeyID("1234");

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final Use use = Use.ENCRYPTION;
		final String kid = "1234";

		RSAKey jwk = new RSAKey(mod, exp, use, JWEAlgorithm.RSA1_5, kid, null, null, null);

		h.setJWK(jwk);
		h.setX509CertURL(new URL("https://example/cert.b64"));
		h.setX509CertThumbprint(new Base64URL("789iop"));

		List<Base64> certChain = new LinkedList<Base64>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		h.setX509CertChain(certChain);

		h.setAgreementPartyUInfo(new Base64URL("abc"));


		String s = h.toString();

		// Parse back
		h = JWEHeader.parse(s);

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
		assertEquals(Use.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URL("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals(new Base64URL("abc"), h.getAgreementPartyUInfo());

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
		assertEquals(11, h.getIncludedParameters().size());
	}


	public void testCrit()
		throws Exception {

		JWEHeader h = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);

		Set<String> crit = new HashSet<String>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		assertNull(h.getCriticalHeaders());

		h.setCriticalHeaders(crit);

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
}
