/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;


/**
 * Tests interop of OpenSSL generated EC keys for ES256, ES384 and ES512.
 */
public class OpenSSLWithECKeyTest extends TestCase {


	private static ECPublicKey fixAlg(final ECPublicKey key)
		throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance("EC");

		return (ECPublicKey)keyFactory.generatePublic(
			new ECPublicKeySpec(key.getW(), key.getParams()));
	}


	private static ECPrivateKey fixAlg(final ECPrivateKey key)
		throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance("EC");

		return (ECPrivateKey)keyFactory.generatePrivate(
			new ECPrivateKeySpec(key.getS(), key.getParams()));
	}


	private static KeyPair parseKeyPair(final String file)
		throws Exception {

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(file)));
		PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		KeyPair keyPair = converter.getKeyPair(pemKeyPair);
		pemParser.close();
		Security.removeProvider("BC");
		return keyPair;
	}


	public void testES256()
		throws Exception {

		// Extract EC key pair generated with
		// openssl ecparam -genkey -name prime256v1 -noout -out testprivatekey-ec256.pem
		KeyPair keyPair = parseKeyPair("./src/test/keys/test-ec256-key.pem");

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		privateKey = fixAlg(privateKey); // BC parses key alg as ECDSA instead of EC
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
		publicKey = fixAlg(publicKey); // BC parses key alg as ECDSA instead of EC

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

		KeyPair keyPair = parseKeyPair("./src/test/keys/test-ec384-key.pem");

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		privateKey = fixAlg(privateKey); // BC parses key alg as ECDSA instead of EC
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
		publicKey = fixAlg(publicKey); // BC parses key alg as ECDSA instead of EC

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

		KeyPair keyPair = parseKeyPair("./src/test/keys/test-ec512-key.pem");

		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
		privateKey = fixAlg(privateKey); // BC parses key alg as ECDSA instead of EC
		ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
		publicKey = fixAlg(publicKey); // BC parses key alg as ECDSA instead of EC

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
