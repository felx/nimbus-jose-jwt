package com.nimbusds.jose.proc;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;


/**
 * Tests the JOSE object handler interface.
 */
public class JOSEObjectHandlerTest extends TestCase {


	public static class JOSEObjectHandlerImpl implements JOSEObjectHandler<String,SimpleContext> {


		@Override
		public String onPlainObject(PlainObject plainObject, SimpleContext ctx) {
			return "plain";
		}


		@Override
		public String onJWSObject(JWSObject jwsObject, SimpleContext ctx) {
			return "jws";
		}


		@Override
		public String onJWEObject(JWEObject jweObject, SimpleContext ctx) {
			return "jwe";
		}
	}


	public void testParsePlainObject()
		throws Exception {

		PlainObject plainObject = new PlainObject(new Payload("Hello world!"));

		assertEquals("plain", JOSEObject.parse(plainObject.serialize(), new JOSEObjectHandlerImpl(), null));
	}


	public void testParseJWSObject()
		throws Exception {

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"));

		String key = "12345678901234567890123456789012";

		jwsObject.sign(new MACSigner(key));

		assertEquals("jws", JOSEObject.parse(jwsObject.serialize(), new JOSEObjectHandlerImpl(), null));
	}


	public void testJWEObject()
		throws Exception {

		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), new Payload("Hello world"));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic()));

		assertEquals("jwe", JOSEObject.parse(jweObject.serialize(), new JOSEObjectHandlerImpl(), null));
	}
}
