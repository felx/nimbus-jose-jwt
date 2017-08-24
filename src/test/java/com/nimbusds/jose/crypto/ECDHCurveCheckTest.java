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


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.text.ParseException;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Submitted by Antonio Sanso. See iss #210. Modified to suit new checks for
 * iss #217.
 */
public class ECDHCurveCheckTest extends TestCase {
	
	
	private static ECKey generateECJWK(final Curve curve)
		throws Exception {
		
		final ECParameterSpec ecParameterSpec = curve.toECParameterSpec();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();
		
		final ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		
		ECPrivateKey pk = new ECPrivateKey() {
			
			BigInteger bi = new BigInteger(
				"38124166010662753100689735609285807169841714722622367731519061366402702420444");
			
			@Override
			public ECParameterSpec getParams() {
				return ecParameterSpec;
			}
			
			@Override
			public String getFormat() {
				return privateKey.getFormat();
			}
			
			@Override
			public byte[] getEncoded() {
				return bi.toByteArray();
			}
			
			@Override
			public String getAlgorithm() {
				return privateKey.getAlgorithm();
			}
			
			@Override
			public BigInteger getS() {
				return bi;
			}
		};
		
		return new ECKey.Builder(curve, (ECPublicKey) keyPair.getPublic())
			.privateKey(pk)
			.build();
	}
	
	
	public void testCycle_ECDH_ES_Curve_P256_attackPoint1()
		throws Exception {
		
		ECKey ecJWK = generateECJWK(Curve.P_256);
		
		BigInteger privateReceiverKey = ecJWK.toECPrivateKey().getS();
		
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
			EncryptionMethod.A128GCM)
			.agreementPartyUInfo(Base64URL.encode("Alice"))
			.agreementPartyVInfo(Base64URL.encode("Bob"))
			.build();
		
		// attacking point #1 with order 113 //
		BigInteger attackerOrderGroup1 = new BigInteger("113");
		BigInteger receiverPrivateKeyModAttackerOrderGroup1 = privateReceiverKey
			.mod(attackerOrderGroup1);
		
//		System.out.println("The receiver private key is equal to "
//			+ receiverPrivateKeyModAttackerOrderGroup1 + " mod "
//			+ attackerOrderGroup1);
		
		// The malicious JWE contains a public key with order 113
		String maliciousJWE1 = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w";
		JWEObject jweObject1 = null;
		
		try {
			jweObject1 = JWEObject.parse(maliciousJWE1);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWE header: Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
		}
		
//		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
////		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
//
//		try {
//			jweObject1.decrypt(decrypter);
//			fail();
//		} catch (JOSEException e) {
//			assertEquals("Invalid ephemeral public key: Point not on expected curve", e.getMessage());
//		}
		
		// this proof that receiverPrivateKey is equals 26 % 113
//		assertEquals("Gambling is illegal at Bushwood sir, and I never slice.",
//			jweObject1.getPayload().toString());
		
		// THIS CAN BE DOIN MANY TIME
		// ....
		// AND THAN CHINESE REMAINDER THEOREM FTW
	}
	
	
	public void testCycle_ECDH_ES_Curve_P256_attackPoint2()
		throws Exception {
		
		ECKey ecJWK = generateECJWK(Curve.P_256);
		
		BigInteger privateReceiverKey = ecJWK.toECPrivateKey().getS();
		
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
			EncryptionMethod.A128GCM)
			.agreementPartyUInfo(Base64URL.encode("Alice"))
			.agreementPartyVInfo(Base64URL.encode("Bob"))
			.build();
		
		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		
		// attacking point #2 with order 2447 //
		BigInteger attackerOrderGroup2 = new BigInteger("2447");
		BigInteger receiverPrivateKeyModAttackerOrderGroup2 = privateReceiverKey
			.mod(attackerOrderGroup2);
		
//		System.out.println("The receiver private key is equal to "
//			+ receiverPrivateKeyModAttackerOrderGroup2 + " mod "
//			+ attackerOrderGroup2);
		
		// The malicious JWE contains a public key with order 2447
		String maliciousJWE2 = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A";
		
		JWEObject jweObject2 = null;
		
		try {
			jweObject2 = JWEObject.parse(maliciousJWE2);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWE header: Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
		}
//		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		
//		try {
//			jweObject2.decrypt(decrypter);
//			fail();
//		} catch (JOSEException e) {
//			assertEquals("Invalid ephemeral public key: Point not on expected curve", e.getMessage());
//		}
		
		// this proof that receiverPrivateKey is equals 2446 % 2447
//		assertEquals("Gambling is illegal at Bushwood sir, and I never slice.",
//			jweObject2.getPayload().toString());
		
		// THIS CAN BE DOIN MANY TIME
		// ....
		// AND THAN CHINESE REMAINDER THEOREM FTW
	}
}
