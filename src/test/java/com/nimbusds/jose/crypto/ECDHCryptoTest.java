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


import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.HashSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import org.jose4j.jwe.JsonWebEncryption;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.Container;


/**
 * Tests ECDH encryption and decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-09-18
 */
public class ECDHCryptoTest extends TestCase {


	private static ECKey generateECJWK(final ECKey.Curve curve)
		throws Exception {

		ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();

		return new ECKey.Builder(curve, (ECPublicKey)keyPair.getPublic()).
			privateKey((ECPrivateKey) keyPair.getPrivate()).
			build();
	}


	public void testCycle_ECDH_ES_Curve_P256()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_256, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P256_A128KW()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_256, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P384()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_384);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_384, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P384_A128KW()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_384);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_384, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P521()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_521);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_521, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P521_A128KW()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_521);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDHEncrypter encrypter = new ECDHEncrypter(ecJWK.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_521, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P256_DecryptWithJose4j()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256CBC_HS512).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		// Encrypt
		jweObject.encrypt(new ECDHEncrypter(ecJWK.toECPublicKey()));

		// Decrypt
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setCompactSerialization(jweObject.serialize());
		jwe.setKey(ecJWK.toECPrivateKey());
		assertEquals("Hello world!", jwe.getPlaintextString());
	}


	public void testCycle_ECDH_ES_Curve_P256_EncryptWithJose4j()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		// Encrypt
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setAlgorithmHeaderValue(JWEAlgorithm.ECDH_ES.getName());
		jwe.setEncryptionMethodHeaderParameter(EncryptionMethod.A192CBC_HS384.getName());
		jwe.setPayload("Hello world!");
		jwe.setKey(ecJWK.toECPublicKey());
		String jweString = jwe.getCompactSerialization();

		// Decrypt
		JWEObject jweObject = JWEObject.parse(jweString);
		jweObject.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey()));
		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_A128KW_Curve_P256_DecryptWithJose4j()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(
			JWEAlgorithm.ECDH_ES_A128KW,
			EncryptionMethod.A256CBC_HS512).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		// Encrypt
		jweObject.encrypt(new ECDHEncrypter(ecJWK.toECPublicKey()));

		// Decrypt
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setCompactSerialization(jweObject.serialize());
		jwe.setKey(ecJWK.toECPrivateKey());
		assertEquals("Hello world!", jwe.getPlaintextString());
	}


	public void testCycle_ECDH_ES_A128KW_Curve_P256_EncryptWithJose4j()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		// Encrypt
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setAlgorithmHeaderValue(JWEAlgorithm.ECDH_ES_A128KW.getName());
		jwe.setEncryptionMethodHeaderParameter(EncryptionMethod.A192CBC_HS384.getName());
		jwe.setPayload("Hello world!");
		jwe.setKey(ecJWK.toECPublicKey());
		String jweString = jwe.getCompactSerialization();

		// Decrypt
		JWEObject jweObject = JWEObject.parse(jweString);
		jweObject.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey()));
		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCookbookExample_ES_steps()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7520#section-5.5

		final String plainText = "You can trust us to stick with you through thick and " +
			"thin–to the bitter end. And you can trust us to "+
			"keep any secret of yours–closer than you keep it " +
			"yourself. But you cannot trust us to let you face trouble " +
			"alone, and go off without a word. We are your friends, Frodo.";

		final ECKey ecJWK = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"kid\": \"meriadoc.brandybuck@buckland.example\"," +
			"\"use\": \"enc\"," +
			"\"crv\": \"P-256\"," +
			"\"x\": \"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0\"," +
			"\"y\": \"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw\"," +
			"\"d\": \"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8\"" +
			"}");

		final ECKey epk = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"crv\": \"P-256\"," +
			"\"x\": \"mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA\"," +
			"\"y\": \"8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs\"," +
			"\"d\": \"AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM\"" +
			"}");


		SecretKey Z = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), epk.toECPrivateKey(), null);

		ConcatKDF concatKDF = new ConcatKDF("SHA-256");

		SecretKey derivedKey = concatKDF.deriveKey(
			Z,
			256,
			ConcatKDF.encodeStringData("A128CBC-HS256"),
			ConcatKDF.encodeDataWithLength((Base64URL) null),
			ConcatKDF.encodeDataWithLength((Base64URL) null),
			ConcatKDF.encodeIntData(256),
			ConcatKDF.encodeNoData());

		assertEquals(256, ByteUtils.bitLength(derivedKey.getEncoded()));
		Base64URL expectedDerivedKey = new Base64URL("hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc");
		assertEquals(expectedDerivedKey, Base64URL.encode(derivedKey.getEncoded()));

		final Base64URL header = new Base64URL(
			"eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW" +
			"NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi" +
			"LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF" +
			"lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0" +
			"RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ");

		JWEHeader jweHeader = JWEHeader.parse(header);
		assertEquals(JWEAlgorithm.ECDH_ES, jweHeader.getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweHeader.getEncryptionMethod());

		ECKey epkParsed = jweHeader.getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_256, epk.getCurve());
		assertEquals("mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA", epkParsed.getX().toString());
		assertEquals("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs", epkParsed.getY().toString());

		final byte[] aad = AAD.compute(header);

		Base64URL iv = new Base64URL("yc9N8v5sYyv3iGQT926IUg");

		final AuthenticatedCipherText authCipherText = AESCBC.encryptAuthenticated(
			derivedKey,
			iv.decode(),
			plainText.getBytes(Charset.forName("UTF-8")),
			aad,
			null,
			null);

		final Base64URL expectedCipherText = new Base64URL(
			"BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9" +
			"IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e" +
			"vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-" +
			"IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI" +
			"-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7" +
			"MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61" +
			"95_JGG2m9Csg");
		assertEquals(expectedCipherText, Base64URL.encode(authCipherText.getCipherText()));

		final Base64URL expectedAuthTag = new Base64URL("WCCkNa-x4BeB9hIDIfFuhg");
		assertEquals(expectedAuthTag, Base64URL.encode(authCipherText.getAuthenticationTag()));
	}


	public void testCookbookExample_ES_A128KW_steps()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7520#section-5.4

		final String plainText = "You can trust us to stick with you through thick and " +
			"thin–to the bitter end. And you can trust us to "+
			"keep any secret of yours–closer than you keep it " +
			"yourself. But you cannot trust us to let you face trouble " +
			"alone, and go off without a word. We are your friends, Frodo.";

		final ECKey ecJWK = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"kid\": \"peregrin.took@tuckborough.example\"," +
			"\"use\": \"enc\"," +
			"\"crv\": \"P-384\"," +
			"\"x\": \"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2\"," +
			"\"y\": \"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP\"," +
			"\"d\": \"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j\"" +
			"}");

		final ECKey epk = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"crv\": \"P-384\"," +
			"\"x\": \"uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3\"," +
			"\"y\": \"sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0\"," +
			"\"d\": \"D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8WfwhinUfWJg\"" +
			"}");

		SecretKey Z = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), epk.toECPrivateKey(), null);

		ConcatKDF concatKDF = new ConcatKDF("SHA-256");

		SecretKey derivedKey = concatKDF.deriveKey(
			Z,
			128,
			ConcatKDF.encodeStringData(JWEAlgorithm.ECDH_ES_A128KW.getName()),
			ConcatKDF.encodeDataWithLength((Base64URL) null),
			ConcatKDF.encodeDataWithLength((Base64URL) null),
			ConcatKDF.encodeIntData(128),
			ConcatKDF.encodeNoData());

		SecretKey cek = new SecretKeySpec(new Base64URL("Nou2ueKlP70ZXDbq9UrRwg").decode(), "AES");
		Base64URL encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, derivedKey, null));

		final Base64URL expectedEncryptedKey = new Base64URL("0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2");
		assertEquals(expectedEncryptedKey, encryptedKey);

		final Base64URL header = new Base64URL(
			"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH" +
			"Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt" +
			"Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH" +
			"hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy" +
			"ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT" +
			"h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0");

		JWEHeader jweHeader = JWEHeader.parse(header);
		assertEquals(JWEAlgorithm.ECDH_ES_A128KW, jweHeader.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, jweHeader.getEncryptionMethod());

		ECKey epkParsed = jweHeader.getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_384, epk.getCurve());
		assertEquals("uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3", epkParsed.getX().toString());
		assertEquals("sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0", epkParsed.getY().toString());

		final byte[] aad = AAD.compute(header);

		Base64URL iv = new Base64URL("mH-G2zVqgztUtnW_");

		final AuthenticatedCipherText authCipherText = AESGCM.encrypt(
			cek,
			new Container<>(iv.decode()),
			plainText.getBytes(Charset.forName("UTF-8")),
			aad,
			BouncyCastleProviderSingleton.getInstance()); // Provider

		final Base64URL expectedCipherText = new Base64URL(
			"tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP" +
			"WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0" +
			"IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc" +
			"Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0" +
			"3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu" +
			"07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ");
		assertEquals(expectedCipherText, Base64URL.encode(authCipherText.getCipherText()));

		final Base64URL expectedAuthTag = new Base64URL("WuGzxmcreYjpHGJoa17EBg");
		assertEquals(expectedAuthTag, Base64URL.encode(authCipherText.getAuthenticationTag()));
	}


	public void testCookbookExample_ECDH_ES_A128KW()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.4

		ECKey ecJWK = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"kid\": \"peregrin.took@tuckborough.example\"," +
			"\"use\": \"enc\"," +
			"\"crv\": \"P-384\"," +
			"\"x\": \"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2\"," +
			"\"y\": \"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP\"," +
			"\"d\": \"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j\"" +
			"}");

		String jwe =
			"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH" +
			"Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt" +
			"Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH" +
			"hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy" +
			"ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT" +
			"h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0" +
			"." +
			"0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2" +
			"." +
			"mH-G2zVqgztUtnW_" +
			"." +
			"tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP" +
			"WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0" +
			"IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc" +
			"Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0" +
			"3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu" +
			"07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ" +
			"." +
			"WuGzxmcreYjpHGJoa17EBg";

		JWEObject jweObject = JWEObject.parse(jwe);

		assertEquals(JWEAlgorithm.ECDH_ES_A128KW, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, jweObject.getHeader().getEncryptionMethod());

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_384, epk.getCurve());
		assertEquals("uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3", epk.getX().toString());
		assertEquals("sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0", epk.getY().toString());

		ECDHDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.",
			jweObject.getPayload().toString());
	}


	public void testCookbookExample_ECDH_ES_A128CBC_HS256()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.5

		ECKey ecJWK = ECKey.parse("{" +
			"\"kty\": \"EC\"," +
			"\"kid\": \"meriadoc.brandybuck@buckland.example\"," +
			"\"use\": \"enc\"," +
			"\"crv\": \"P-256\"," +
			"\"x\": \"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0\"," +
			"\"y\": \"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw\"," +
			"\"d\": \"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8\"" +
			"}");

		String jwe = "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW" +
			"NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi" +
			"LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF" +
			"lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0" +
			"RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ" +
			"." +
			"." +
			"yc9N8v5sYyv3iGQT926IUg" +
			"." +
			"BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9" +
			"IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e" +
			"vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-" +
			"IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI" +
			"-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7" +
			"MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61" +
			"95_JGG2m9Csg" +
			"." +
			"WCCkNa-x4BeB9hIDIfFuhg";

		JWEObject jweObject = JWEObject.parse(jwe);
		assertEquals(JWEAlgorithm.ECDH_ES, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweObject.getHeader().getEncryptionMethod());

		ECKey epk = jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(ECKey.Curve.P_256, epk.getCurve());
		assertEquals("mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA", epk.getX().toString());
		assertEquals("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs", epk.getY().toString());

		jweObject.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey()));

		final String expectedPlainText =
			"You can trust us to stick with you through thick and " +
			"thin–to the bitter end. And you can trust us to "+
			"keep any secret of yours–closer than you keep it " +
			"yourself. But you cannot trust us to let you face trouble " +
			"alone, and go off without a word. We are your friends, Frodo.";

		assertEquals(expectedPlainText, jweObject.getPayload().toString());
	}


	private static KeyPair createUnsupportedECKeyPair()
		throws Exception {

		ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec("secp224r1");

		ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(curveParams.getName(),
			curveParams.getCurve(),
			curveParams.getG(),
			curveParams.getN());

		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
		generator.initialize(ecParameterSpec);
		return generator.generateKeyPair();
	}


	public void testRejectECKeyWithUnsupportedCurve()
		throws Exception {

		KeyPair keyPair = createUnsupportedECKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
		ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();

		try {
			new ECDHEncrypter(ecPublicKey);
			fail();
		} catch (JOSEException e) {
			// ok
		}

		try {
			new ECDHDecrypter(ecPrivateKey);
			fail();
		} catch (JOSEException e) {
			// ok
		}
	}


	public void testRejectECJWKWithUnsupportedCurve()
		throws Exception {

		KeyPair keyPair = createUnsupportedECKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
		ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();

		ECKey ecJWK = new ECKey.Builder(new ECKey.Curve("P-224"), ecPublicKey).privateKey(ecPrivateKey).build();

		try {
			new ECDHEncrypter(ecJWK);
			fail();
		} catch (JOSEException e) {
			// ok
		}

		try {
			new ECDHDecrypter(ecJWK);
			fail();
		} catch (JOSEException e) {
			// ok
		}
	}


	public void testECKeyGetters()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		ECPublicKey ecPublicKey = ecJWK.toECPublicKey();
		ECDHEncrypter encrypter = new ECDHEncrypter(ecPublicKey);
		assertEquals(ecPublicKey, encrypter.getPublicKey());

		ECPrivateKey ecPrivateKey = ecJWK.toECPrivateKey();
		ECDHDecrypter decrypter = new ECDHDecrypter(ecPrivateKey);
		assertEquals(ecPrivateKey, decrypter.getPrivateKey());
	}


	public void testCritParamDeferral()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new ECDHEncrypter(ecJWK));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey(), new HashSet<>(Collections.singletonList("exp"))));

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamReject()
		throws Exception {

		ECKey ecJWK = generateECJWK(ECKey.Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new ECDHEncrypter(ecJWK));

		jweObject = JWEObject.parse(jweObject.serialize());

		try {
			jweObject.decrypt(new ECDHDecrypter(ecJWK));
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}
}
