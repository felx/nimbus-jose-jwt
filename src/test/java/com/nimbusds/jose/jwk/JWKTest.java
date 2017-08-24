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

package com.nimbusds.jose.jwk;


import java.io.File;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * Tests the base JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-08-24
 */
public class JWKTest extends TestCase {
	

	public void testMIMEType() {

		assertEquals("application/jwk+json; charset=UTF-8", JWK.MIME_TYPE);
	}
	
	
	public void testParseRSAJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		assertEquals(KeyType.RSA, jwk.getKeyType());
		assertNull(jwk.getAlgorithm());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertNull(jwk.getKeyOperations());
		assertEquals(1, jwk.getX509CertChain().size());
		assertNull(jwk.getX509CertThumbprint());
		assertNotNull(jwk.getX509CertSHA256Thumbprint());
		assertFalse(jwk.isPrivate());
		assertTrue(jwk instanceof RSAKey);
	}
	
	
	public void testParseECJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		assertEquals(KeyType.EC, jwk.getKeyType());
		assertNull(jwk.getAlgorithm());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertNull(jwk.getKeyOperations());
		assertEquals(1, jwk.getX509CertChain().size());
		assertNull(jwk.getX509CertThumbprint());
		assertNotNull(jwk.getX509CertSHA256Thumbprint());
		assertFalse(jwk.isPrivate());
		assertTrue(jwk instanceof ECKey);
		assertEquals(Curve.P_256, ((ECKey)jwk).getCurve());
	}
	
	
	public void testLoadRSAJWKFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		// Generate certificate
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
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new Certificate[]{cert});
		
		// Load
		RSAKey rsaKey = (RSAKey) JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(rsaKey);
		assertEquals(KeyUse.SIGNATURE, rsaKey.getKeyUse());
		assertEquals("1", rsaKey.getKeyID());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertNotNull(rsaKey.getX509CertSHA256Thumbprint());
		assertTrue(rsaKey.isPrivate());
		
		// Try to load with bad pin
		try {
			JWK.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't retrieve private RSA key (bad pin?): Cannot recover key", e.getMessage());
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadECJWKFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(Curve.P_521.toECParameterSpec());
		KeyPair kp = gen.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey)kp.getPrivate();
		
		// Generate certificate
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
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new java.security.cert.Certificate[]{cert});
		
		// Load
		ECKey ecKey = (ECKey)JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(ecKey);
		assertEquals(Curve.P_521, ecKey.getCurve());
		assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
		assertEquals("1", ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertNotNull(ecKey.getX509CertSHA256Thumbprint());
		assertTrue(ecKey.isPrivate());
		
		// Try to load with bad pin
		try {
			JWK.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't retrieve private EC key (bad pin?): Cannot recover key", e.getMessage());
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadSecretKeyFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey secretKey = gen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		OctetSequenceKey octJWK = (OctetSequenceKey)JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(octJWK);
		assertEquals("1", octJWK.getKeyID());
		assertTrue(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray()));
	}
	
	
	public void testLoadJWK_notFound()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		assertNull(JWK.load(keyStore, "no-such-key-id", "".toCharArray()));
	}
	
	
	public void testParseOKP()
		throws Exception {
		
		String json = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
		
		JWK jwk = JWK.parse(json);
		assertEquals(KeyType.OKP, jwk.getKeyType());
		
		OctetKeyPair okp = (OctetKeyPair)jwk;
		
		assertEquals(Curve.X448, okp.getCurve());
		assertEquals("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk", okp.getX().toString());
		assertEquals("Dave", okp.getKeyID());
		assertFalse(okp.isPrivate());
	}
}
