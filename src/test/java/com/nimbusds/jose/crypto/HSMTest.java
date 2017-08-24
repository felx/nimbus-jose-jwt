/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static org.junit.Assert.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * HSM test with Nitrokey.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-06
 */
public class HSMTest {
	
	
	private static String HSM_CONFIG =
		"name = NitroKeyHSM\n" +
		"library = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n" +
		"slotListIndex = 1\n" +
		"attributes(*,CKO_PRIVATE_KEY,CKK_RSA) = {\n" +
		"  CKA_SIGN = true\n" +
		"}\n" +
		"attributes(*,CKO_PRIVATE_KEY,CKK_RSA) = {\n" +
		"  CKA_DECRYPT = true\n" +
		"}\n";
	
	
	private static String HSM_PIN = "836019";
	

	private static Provider loadHSMProvider(final String hsmConfig) {
		InputStream is = new ByteArrayInputStream(hsmConfig.getBytes(Charset.forName("UTF-8")));
		return new sun.security.pkcs11.SunPKCS11(is);
	}
	
	
	private static KeyStore loadHSMKeyStore(final Provider hsmProvider, final String userPin)
		throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		
		KeyStore keyStore = KeyStore.getInstance("PKCS11", hsmProvider);
		keyStore.load(null, userPin.toCharArray());
		return keyStore;
	}
	
	
	private static String generateRandomKeyID() {
		
		byte[] bytes = new byte[4];
		new SecureRandom().nextBytes(bytes);
		return Base64URL.encode(bytes).toString();
	}
	
	
	private static String generateRSAKeyWithSelfSignedCert(final KeyStore hsmKeyStore)
		throws NoSuchAlgorithmException, IOException, OperatorCreationException, KeyStoreException {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", hsmKeyStore.getProvider());
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			keyPair.getPublic()
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		signerBuilder.setProvider(hsmKeyStore.getProvider());
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(keyPair.getPrivate()));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		assertNotNull(cert);
		
		String keyID = generateRandomKeyID();

		hsmKeyStore.setKeyEntry(keyID, keyPair.getPrivate(), "".toCharArray(), new Certificate[]{cert});
		
		return keyID;
	}
	
	
	private static String generateECKeyWithSelfSignedCert(final KeyStore hsmKeyStore)
		throws NoSuchAlgorithmException, IOException, OperatorCreationException, KeyStoreException, InvalidAlgorithmParameterException {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", hsmKeyStore.getProvider());
		keyPairGenerator.initialize(Curve.P_256.toECParameterSpec());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			keyPair.getPublic()
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		signerBuilder.setProvider(hsmKeyStore.getProvider());
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(keyPair.getPrivate()));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		assertNotNull(cert);
		
		String keyID = generateRandomKeyID();

		hsmKeyStore.setKeyEntry(keyID, keyPair.getPrivate(), "".toCharArray(), new Certificate[]{cert});
		
		return keyID;
	}
	
	
//	@Test
	public void testRSASign()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String keyID = generateRSAKeyWithSelfSignedCert(hsmKeyStore);
		
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
		assertFalse(privateKey instanceof RSAPrivateKey);
			
		RSASSASigner signer = new RSASSASigner(privateKey);
		signer.getJCAContext().setProvider(hsmProvider);
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyID).build(),
			new JWTClaimsSet.Builder().subject("alice").build());
		
		jwt.sign(signer);
		String jwtString = jwt.serialize();
			
		RSAPublicKey publicKey = (RSAPublicKey)hsmKeyStore.getCertificate(keyID).getPublicKey();
		assertTrue(SignedJWT.parse(jwtString).verify(new RSASSAVerifier(publicKey)));
		new RSAKey.Builder(publicKey).keyID(keyID).build();
		
		hsmKeyStore.deleteEntry(keyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testRSASignWithJWK()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String keyID = generateRSAKeyWithSelfSignedCert(hsmKeyStore);
		
		RSAPublicKey publicKey = (RSAPublicKey)hsmKeyStore.getCertificate(keyID).getPublicKey();
		
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
		assertFalse(privateKey instanceof RSAPrivateKey);
		
		RSAKey rsaJWK = new RSAKey.Builder(publicKey)
			.keyID(keyID)
			.privateKey(privateKey)
			.build();
		
		RSASSASigner signer = new RSASSASigner(rsaJWK);
		signer.getJCAContext().setProvider(hsmProvider);
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			new JWTClaimsSet.Builder().subject("alice").build());
		
		jwt.sign(signer);
		String jwtString = jwt.serialize();
		
		assertTrue(SignedJWT.parse(jwtString).verify(new RSASSAVerifier(publicKey)));
		new RSAKey.Builder(publicKey).keyID(keyID).build();
		
		hsmKeyStore.deleteEntry(keyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testRSADecryptWithHSM()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String keyID = generateRSAKeyWithSelfSignedCert(hsmKeyStore);
		
		RSAPublicKey publicKey = (RSAPublicKey)hsmKeyStore.getCertificate(keyID).getPublicKey();
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
		assertFalse(privateKey instanceof RSAPrivateKey);
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM).keyID(keyID).build(),
			new Payload("Hello world!"));
		
		jweObject.encrypt(encrypter);
		
		String jwe = jweObject.serialize();
		
		jweObject = JWEObject.parse(jwe);
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		decrypter.getJCAContext().setKeyEncryptionProvider(hsmProvider);
		
		try {
			jweObject.decrypt(decrypter);
		} catch (JOSEException e) {
			System.out.println("CEK exception: " + decrypter.getCEKDecryptionException());
			fail(e.getMessage());
		}
		
		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
		assertEquals("Hello world!", jweObject.getPayload().toString());
		
		hsmKeyStore.deleteEntry(keyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testECSign()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String keyID = generateECKeyWithSelfSignedCert(hsmKeyStore);
		
		ECPublicKey publicKey = (ECPublicKey)hsmKeyStore.getCertificate(keyID).getPublicKey();
		
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
		assertFalse(privateKey instanceof ECPrivateKey);
		
		ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey)
			.privateKey(privateKey)
			.keyID(keyID)
			.build();
		
		ECDSASigner signer = new ECDSASigner(ecJWK);
		signer.getJCAContext().setProvider(hsmProvider);
		
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
				new JWTClaimsSet.Builder().subject("alice").build());
		
		jwt.sign(signer);
		String jwtString = jwt.serialize();
		
		assertTrue(SignedJWT.parse(jwtString).verify(new ECDSAVerifier(publicKey)));
		new ECKey.Builder(Curve.P_256, publicKey).keyID(keyID).build();
		
		hsmKeyStore.deleteEntry(keyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testECSignWithJWK()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String keyID = generateECKeyWithSelfSignedCert(hsmKeyStore);
		
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
		assertFalse(privateKey instanceof ECPrivateKey);
			
		ECDSASigner signer = new ECDSASigner(privateKey, Curve.P_256);
		signer.getJCAContext().setProvider(hsmProvider);
		
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyID).build(),
				new JWTClaimsSet.Builder().subject("alice").build());
			
		jwt.sign(signer);
		String jwtString = jwt.serialize();
		
		ECPublicKey publicKey = (ECPublicKey)hsmKeyStore.getCertificate(keyID).getPublicKey();
		assertTrue(SignedJWT.parse(jwtString).verify(new ECDSAVerifier(publicKey)));
		new ECKey.Builder(Curve.P_256, publicKey).keyID(keyID).build();
		
		hsmKeyStore.deleteEntry(keyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testLoadJWKs()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		assertEquals("PKCS11", hsmKeyStore.getType());
		
		int numKeys = hsmKeyStore.size();
		
		String rsaKeyID = generateRSAKeyWithSelfSignedCert(hsmKeyStore);
		String ecKeyID = generateECKeyWithSelfSignedCert(hsmKeyStore);
		
		// Load individual RSA JWK
		RSAKey rsaJWK = RSAKey.load(hsmKeyStore, rsaKeyID, "".toCharArray());
		assertEquals(rsaKeyID, rsaJWK.getKeyID());
		assertNull(rsaJWK.getKeyUse());
		assertTrue(rsaJWK.isPrivate());
		
		// Load individual EC JWK
		ECKey ecJWK = ECKey.load(hsmKeyStore, ecKeyID, "".toCharArray());
		assertEquals(ecKeyID, ecJWK.getKeyID());
		assertNull(ecJWK.getKeyUse());
		assertTrue(ecJWK.isPrivate());
		
		// Load JWK set
		JWKSet jwkSet = JWKSet.load(hsmKeyStore, null);
		assertTrue(jwkSet.getKeyByKeyId(rsaKeyID) instanceof RSAKey);
		assertTrue(jwkSet.getKeyByKeyId(ecKeyID) instanceof ECKey);
		
		hsmKeyStore.deleteEntry(rsaKeyID);
		hsmKeyStore.deleteEntry(ecKeyID);
		
		assertEquals(numKeys, hsmKeyStore.size());
	}
	
	
//	@Test
	public void testAvailableAlgs() {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		System.out.println("Properties:");
		
		for (String propName: hsmProvider.stringPropertyNames()) {
			System.out.println(propName + " = " + hsmProvider.getProperty(propName));
		}
		
		
		System.out.println("Services:");
		
		for (Provider.Service service: hsmProvider.getServices()) {
			System.out.println(service.getType() + " : " + service.getAlgorithm());
		}
	}
}
