package com.nimbusds.jose;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;


/**
 * Tests the JOSE object handler interface.
 */
public class JOSEObjectHandlerTest extends TestCase {


	public static class JOSEObjectHandlerImpl implements JOSEObjectHandler<String> {


		@Override
		public String onPlainObject(PlainObject plainObject) {
			return "plain";
		}


		@Override
		public String onJWSObject(JWSObject jwsObject) {
			return "jws";
		}


		@Override
		public String onJWEObject(JWEObject jweObject) {
			return "jwe";
		}
	}


	public void testParsePlainObject()
		throws Exception {

		PlainObject plainObject = new PlainObject(new Payload("Hello world!"));

		assertEquals("plain", JOSEObject.parse(plainObject.serialize(), new JOSEObjectHandlerImpl()));
	}


	public void testParseJWSObject()
		throws Exception {

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"));

		String key = "abcdef123456789";

		jwsObject.sign(new MACSigner(key));

		assertEquals("jws", JOSEObject.parse(jwsObject.serialize(), new JOSEObjectHandlerImpl()));
	}


	public void testJWEObject()
		throws Exception {

		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), new Payload("Hello world"));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic()));

		assertEquals("jwe", JOSEObject.parse(jweObject.serialize(), new JOSEObjectHandlerImpl()));
	}
}
