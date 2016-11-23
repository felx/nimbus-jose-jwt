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
import java.util.Date;
import java.util.Enumeration;

import static org.junit.Assert.assertNotNull;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;


public class HSMTest {
	
	
	private static String HSM_CONFIG =
		"name = NitroKeyHSM\n" +
		"library = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n" +
		"slotListIndex = 1\n";
	
	
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
	
	
	private static String generateRSAKey(final KeyStore hsmKeyStore)
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
	
	
	@Test
	public void testLoadHSMKeyStore()
		throws Exception {
		
		Provider hsmProvider = loadHSMProvider(HSM_CONFIG);
		
		KeyStore hsmKeyStore = loadHSMKeyStore(hsmProvider, HSM_PIN);
		
		System.out.println("Key store type: " + hsmKeyStore.getType());
		
		System.out.println("Number of keys in HSM: " + hsmKeyStore.size());
		
		System.out.println("HSM key aliases: ");
		
		Enumeration<String> keyAliases = hsmKeyStore.aliases();
		while(keyAliases.hasMoreElements()) {
			System.out.println("\tKey alias: " + keyAliases.nextElement());
		}
		
		String keyID = generateRSAKey(hsmKeyStore);
		
		PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyID, "".toCharArray());
			
		RSASSASigner signer = new RSASSASigner(privateKey);
		signer.getJCAContext().setProvider(hsmProvider);
			
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("Hello, world!"));
		jwsObject.sign(signer);
		System.out.println(jwsObject.serialize());
		
		hsmKeyStore.deleteEntry(keyID);
	}
}
