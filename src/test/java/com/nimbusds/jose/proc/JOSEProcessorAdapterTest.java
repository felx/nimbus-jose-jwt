package com.nimbusds.jose.proc;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;


/**
 * Tests the JOSE object handler adapter.
 */
public class JOSEProcessorAdapterTest extends TestCase {


	public void testParsePlainObject()
		throws Exception {

		PlainObject plainObject = new PlainObject(new Payload("Hello world!"));

		assertNull(JOSEObject.parse(plainObject.serialize(), new JOSEProcessorAdapter<String,SimpleSecurityContext>(), null));
	}


	public void testParseJWSObject()
		throws Exception {

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"));

		String key = "12345678901234567890123456789012";

		jwsObject.sign(new MACSigner(key));

		assertNull(JOSEObject.parse(jwsObject.serialize(), new JOSEProcessorAdapter<String,SimpleSecurityContext>(), null));
	}


	public void testJWEObject()
		throws Exception {

		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), new Payload("Hello world"));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic());
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		assertNull(JOSEObject.parse(jweObject.serialize(), new JOSEProcessorAdapter<String, SimpleSecurityContext>(), null));
	}
}
