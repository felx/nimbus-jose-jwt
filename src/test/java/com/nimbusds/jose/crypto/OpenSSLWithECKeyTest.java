package com.nimbusds.jose.crypto;


import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import junit.framework.TestCase;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;


/**
 * Tests interop of OpenSSL generated EC keys for ES256, ES384 and ES512.
 */
public class OpenSSLWithECKeyTest extends TestCase {


	public void testES256()
		throws Exception {

		// Extract EC key pair generated with
		// openssl ecparam -genkey -name prime256v1 -noout -out testprivatekey-ec256.pem

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream("./src/test/keys/test-ec256-key.pem")));
		PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		KeyPair keyPair = converter.getKeyPair(pemKeyPair);
		pemParser.close();

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();

		// Sign
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload("Hello world!"));
		jwsObject.sign(new ECDSASigner(privateKey));

		// Serialise
		String compactJWS = jwsObject.serialize();

		// Verify
		jwsObject = JWSObject.parse(compactJWS);
		assertTrue(jwsObject.verify(new ECDSAVerifier(publicKey)));
	}


	public void testES384()
		throws Exception {

		// Extract EC key pair generated with
		// openssl ecparam -genkey -name secp384r1 -noout -out test-ec384-key.pem

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream("./src/test/keys/test-ec384-key.pem")));
		PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		KeyPair keyPair = converter.getKeyPair(pemKeyPair);
		pemParser.close();

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();

		// Sign
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES384), new Payload("Hello world!"));
		jwsObject.sign(new ECDSASigner(privateKey));

		// Serialise
		String compactJWS = jwsObject.serialize();

		// Verify
		jwsObject = JWSObject.parse(compactJWS);
		assertTrue(jwsObject.verify(new ECDSAVerifier(publicKey)));
	}


	public void testES512()
		throws Exception {

		// Extract EC key pair generated with
		// openssl ecparam -genkey -name secp521r1 -noout -out test-ec512-key.pem

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream("./src/test/keys/test-ec512-key.pem")));
		PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		KeyPair keyPair = converter.getKeyPair(pemKeyPair);
		pemParser.close();

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();

		// Sign
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES512), new Payload("Hello world!"));
		jwsObject.sign(new ECDSASigner(privateKey));

		// Serialise
		String compactJWS = jwsObject.serialize();

		// Verify
		jwsObject = JWSObject.parse(compactJWS);
		assertTrue(jwsObject.verify(new ECDSAVerifier(publicKey)));
	}
}
