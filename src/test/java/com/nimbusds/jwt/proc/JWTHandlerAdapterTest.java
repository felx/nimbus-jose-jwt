package com.nimbusds.jwt.proc;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.*;


/**
 * Tests the JWT handler adapter.
 */
public class JWTHandlerAdapterTest extends TestCase {


	private static ReadOnlyJWTClaimsSet generateClaimsSet() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("c2id.com");
		claimsSet.setSubject("alice");
		return claimsSet;
	}


	public void testParsePlainJWT()
		throws Exception {

		JWT plainJWT = new PlainJWT(generateClaimsSet());

		TestCase.assertNull(JWTParser.parse(plainJWT.serialize(), new JWTHandlerAdapter<String,SimpleSecurityContext>(), null));
	}


	public void testParseSignedJWT()
		throws Exception {

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), generateClaimsSet());

		String key = "12345678901234567890123456789012";

		signedJWT.sign(new MACSigner(key));

		assertNull(JWTParser.parse(signedJWT.serialize(), new JWTHandlerAdapter<String,SimpleSecurityContext>(), null));
	}


	public void testEncryptedJWT()
		throws Exception {

		EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), generateClaimsSet());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic());
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		encryptedJWT.encrypt(encrypter);

		assertNull(JWTParser.parse(encryptedJWT.serialize(), new JWTHandlerAdapter<String,SimpleSecurityContext>(), null));
	}
}
