package com.nimbusds.jose;


import java.net.MalformedURLException;
import java.net.URL;

import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-16)
 */
public class JWEHeaderTest extends TestCase {


	public void testParse1() {
	
		// Example header from JWE spec
		// {"alg":"RSA-OAEP","enc":"A256GCM"}
		String s = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
	
		JWEHeader h = null;
		
		try {
			h = JWEHeader.parse(new Base64URL(s));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(JWEAlgorithm.RSA_OAEP, h.getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		
		assertNull(h.getType());
		assertNull(h.getContentType());
		
		assertTrue(h.getIncludedParameters().contains("alg"));
		assertTrue(h.getIncludedParameters().contains("enc"));
		assertEquals(2, h.getIncludedParameters().size());
	}
	
	
	public void testParse2() {
	
		// Example header from JWE spec
		// {"alg":"RSA1_5","enc":"A128CBC+HS256"}
		String s = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0";
	
		JWEHeader h = null;
		
		try {
			h = JWEHeader.parse(new Base64URL(s));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
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
	
		JWEHeader h = new JWEHeader(JWEAlgorithm.RSA1_5, 
		                            EncryptionMethod.A256GCM);
		
		h.setType(new JOSEObjectType("JWT"));
		h.setCompressionAlgorithm(CompressionAlgorithm.DEF);
		h.setJWKURL(new URL("https://example.com/jku.json"));
		h.setKeyID("1234");
		
		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final Use use = Use.ENCRYPTION;
		final String kid = "1234";
		
		RSAKey jwk = new RSAKey(mod, exp, use, kid);
		
		h.setJWK(jwk);
		h.setX509CertURL(new URL("https://example/cert.b64"));
		h.setX509CertThumbprint(new Base64URL("789iop"));
		
		Base64[] certChain = new Base64[3];
		certChain[0] = new Base64("asd");
		certChain[1] = new Base64("fgh");
		certChain[2] = new Base64("jkl");
		
		h.setX509CertChain(certChain);
		
		
		String s = h.toString();
		
		// Parse back
		
		try {
			h = JWEHeader.parse(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URL("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());
		
		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getExponent());
		assertEquals(Use.ENCRYPTION, jwk.getKeyUse());
		assertEquals("1234", jwk.getKeyID());
		
		assertEquals(new URL("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		
		certChain = h.getX509CertChain();
		assertEquals(3, certChain.length);
		assertEquals(new Base64("asd"), certChain[0]);
		assertEquals(new Base64("fgh"), certChain[1]);
		assertEquals(new Base64("jkl"), certChain[2]);
		
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
		assertEquals(10, h.getIncludedParameters().size());
	}
}
