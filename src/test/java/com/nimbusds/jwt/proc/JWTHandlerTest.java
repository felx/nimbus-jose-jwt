package com.nimbusds.jwt.proc;


import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.proc.SimpleContext;
import com.nimbusds.jwt.*;


/**
 * Tests the JWT handler interface.
 */
public class JWTHandlerTest extends TestCase {


	public static class JWTHandlerImpl implements JWTHandler<String,SimpleContext> {


		@Override
		public String onPlainJWT(PlainJWT plainJWT, SimpleContext ctx) {
			return "plain";
		}


		@Override
		public String onSignedJWT(SignedJWT signedJWT, SimpleContext ctx) {
			return "signed";
		}


		@Override
		public String onEncryptedJWT(EncryptedJWT encryptedJWT, SimpleContext ctx) {
			return "encrypted";
		}
	}


	private static ReadOnlyJWTClaimsSet generateClaimsSet() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("c2id.com");
		claimsSet.setSubject("alice");
		return claimsSet;
	}


	public void testParsePlainJWT()
		throws Exception {

		JWT plainJWT = new PlainJWT(generateClaimsSet());

		assertEquals("plain", JWTParser.parse(plainJWT.serialize(), new JWTHandlerImpl(), null));
	}


	public void testParseSignedJWT()
		throws Exception {

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), generateClaimsSet());

		String key = "12345678901234567890123456789012";

		signedJWT.sign(new MACSigner(key));

		assertEquals("signed", JWTParser.parse(signedJWT.serialize(), new JWTHandlerImpl(), null));
	}


	public void testEncryptedJWT()
		throws Exception {

		EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), generateClaimsSet());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyGen.generateKeyPair().getPublic());
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		encryptedJWT.encrypt(encrypter);

		assertEquals("encrypted", JWTParser.parse(encryptedJWT.serialize(), new JWTHandlerImpl(), null));
	}
}
