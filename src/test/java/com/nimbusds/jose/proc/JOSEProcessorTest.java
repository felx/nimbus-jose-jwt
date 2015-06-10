package com.nimbusds.jose.proc;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;


/**
 * Tests the JOSE object handler interface.
 */
public class JOSEProcessorTest extends TestCase {


	public static class JOSEProcessorImpl implements JOSEProcessor<String,SimpleSecurityContext> {


		@Override
		public String process(PlainObject plainObject, SimpleSecurityContext ctx) {
			return "plain";
		}


		@Override
		public String verify(JWSObject jwsObject, SimpleSecurityContext ctx) {
			return "jws";
		}


		@Override
		public String decrypt(JWEObject jweObject, SimpleSecurityContext ctx) {
			return "jwe";
		}
	}


	public void testParsePlainObject()
		throws Exception {

		PlainObject plainObject = new PlainObject(new Payload("Hello world!"));

		assertEquals("plain", JOSEObject.parse(plainObject.serialize(), new JOSEProcessorImpl(), null));
	}


	public void testParseJWSObject()
		throws Exception {

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"));

		String key = "12345678901234567890123456789012";

		jwsObject.sign(new MACSigner(key));

		assertEquals("jws", JOSEObject.parse(jwsObject.serialize(), new JOSEProcessorImpl(), null));
	}


	public void testJWEObject()
		throws Exception {

		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), new Payload("Hello world"));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic());
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		assertEquals("jwe", JOSEObject.parse(jweObject.serialize(), new JOSEProcessorImpl(), null));
	}
}
