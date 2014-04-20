package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashSet;

import com.nimbusds.jose.jwk.RSAKey;
import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests RSASSA JWS signing and verification. Uses test RSA keys and vectors
 * from the JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-20)
 */
public class RSASSATest extends TestCase {


	private final static byte[] MOD = {
		(byte)161, (byte)248, (byte) 22, (byte) 10, (byte)226, (byte)227, (byte)201, (byte)180,
		(byte)101, (byte)206, (byte)141, (byte) 45, (byte)101, (byte) 98, (byte) 99, (byte) 54, 
		(byte) 43, (byte)146, (byte)125, (byte)190, (byte) 41, (byte)225, (byte)240, (byte) 36, 
		(byte)119, (byte)252, (byte) 22, (byte) 37, (byte)204, (byte)144, (byte)161, (byte) 54, 
		(byte)227, (byte)139, (byte)217, (byte) 52, (byte)151, (byte)197, (byte)182, (byte)234,

		(byte) 99, (byte)221, (byte)119, (byte) 17, (byte)230, (byte)124, (byte)116, (byte) 41, 
		(byte)249, (byte) 86, (byte)176, (byte)251, (byte)138, (byte)143, (byte)  8, (byte)154, 
		(byte)220, (byte) 75, (byte)105, (byte)137, (byte) 60, (byte)193, (byte) 51, (byte) 63, 
		(byte) 83, (byte)237, (byte)208, (byte) 25, (byte)184, (byte)119, (byte)132, (byte) 37, 
		(byte) 47, (byte)236, (byte)145, (byte) 79, (byte)228, (byte)133, (byte)119, (byte)105,

		(byte) 89, (byte) 75, (byte)234, (byte) 66, (byte)128, (byte)211, (byte) 44, (byte) 15, 
		(byte) 85, (byte)191, (byte) 98, (byte)148, (byte) 79, (byte) 19, (byte)  3, (byte)150, 
		(byte)188, (byte)110, (byte)155, (byte)223, (byte)110, (byte)189, (byte)210, (byte)189, 
		(byte)163, (byte)103, (byte)142, (byte)236, (byte)160, (byte)198, (byte)104, (byte)247, 
		(byte)  1, (byte)179, (byte)141, (byte)191, (byte)251, (byte) 56, (byte)200, (byte) 52, 

		(byte) 44, (byte)226, (byte)254, (byte)109, (byte) 39, (byte)250, (byte)222, (byte) 74, 
		(byte) 90, (byte) 72, (byte)116, (byte)151, (byte)157, (byte)212, (byte)185, (byte)207, 
		(byte)154, (byte)222, (byte)196, (byte)199, (byte) 91, (byte)  5, (byte)133, (byte) 44, 
		(byte) 44, (byte) 15, (byte) 94, (byte)248, (byte)165, (byte)193, (byte)117, (byte)  3,
		(byte)146, (byte)249, (byte) 68, (byte)232, (byte)237, (byte)100, (byte)193, (byte) 16, 

		(byte)198, (byte)182, (byte) 71, (byte) 96, (byte)154, (byte)164, (byte)120, (byte) 58, 
		(byte)235, (byte)156, (byte)108, (byte)154, (byte)215, (byte) 85, (byte) 49, (byte) 48, 
		(byte) 80, (byte) 99, (byte)139, (byte)131, (byte)102, (byte) 92, (byte)111, (byte)111, 
		(byte)122, (byte)130, (byte)163, (byte)150, (byte)112, (byte) 42, (byte) 31, (byte)100, 
		(byte) 27, (byte)130, (byte)211, (byte)235, (byte)242, (byte) 57, (byte) 34, (byte) 25, 

		(byte) 73, (byte) 31, (byte)182, (byte)134, (byte)135, (byte) 44, (byte) 87, (byte) 22, 
		(byte)245, (byte) 10, (byte)248, (byte) 53, (byte)141, (byte)154, (byte)139, (byte)157, 
		(byte) 23, (byte)195, (byte) 64, (byte)114, (byte)143, (byte)127, (byte)135, (byte)216,
		(byte)154, (byte) 24, (byte)216, (byte)252, (byte)171, (byte)103, (byte)173, (byte)132, 
		(byte) 89, (byte) 12, (byte) 46, (byte)207, (byte)117, (byte)147, (byte) 57, (byte) 54, 

		(byte) 60, (byte)  7, (byte)  3, (byte) 77, (byte)111, (byte) 96, (byte)111, (byte)158, 
		(byte) 33, (byte)224, (byte) 84, (byte) 86, (byte)202, (byte)229, (byte)233, (byte)161  };


	private static final byte[] EXP = { 1, 0, 1 };


	private static final byte[] MOD_PRIV = {
		(byte) 18, (byte)174, (byte)113, (byte)164, (byte)105, (byte)205, (byte) 10, (byte) 43,
		(byte)195, (byte)126, (byte) 82, (byte)108, (byte) 69, (byte)  0, (byte) 87, (byte) 31, 
		(byte) 29, (byte) 97, (byte)117, (byte) 29, (byte)100, (byte)233, (byte) 73, (byte)112, 
		(byte)123, (byte) 98, (byte) 89, (byte) 15, (byte)157, (byte) 11, (byte)165, (byte)124, 
		(byte)150, (byte) 60, (byte) 64, (byte) 30, (byte) 63, (byte)207, (byte) 47, (byte) 44,

		(byte)211, (byte)189, (byte)236, (byte)136, (byte)229, (byte)  3, (byte)191, (byte)198, 
		(byte) 67, (byte)155, (byte) 11, (byte) 40, (byte)200, (byte) 47, (byte)125, (byte) 55, 
		(byte)151, (byte)103, (byte) 31, (byte) 82, (byte) 19, (byte)238, (byte)216, (byte)193, 
		(byte) 90, (byte) 37, (byte)216, (byte)213, (byte)206, (byte)160, (byte)  2, (byte) 94, 
		(byte)227, (byte)171, (byte) 46, (byte)139, (byte)127, (byte)121, (byte) 33, (byte)111,

		(byte)198, (byte) 59, (byte)234, (byte) 86, (byte) 39, (byte) 83, (byte)180, (byte) 6, 
		(byte) 68, (byte)198, (byte)161, (byte) 81, (byte) 39, (byte)217, (byte)178, (byte)149, 
		(byte) 69, (byte) 64, (byte)160, (byte)187, (byte)225, (byte)163, (byte)  5, (byte) 86, 
		(byte)152, (byte) 45, (byte) 78, (byte)159, (byte)222, (byte) 95, (byte)100, (byte) 37, 
		(byte)241, (byte) 77, (byte) 75, (byte)113, (byte) 52, (byte) 65, (byte)181, (byte) 93, 

		(byte)199, (byte) 59, (byte)155, (byte) 74, (byte)237, (byte)204, (byte)146, (byte)172, 
		(byte)227, (byte)146, (byte)126, (byte) 55, (byte)245, (byte)125, (byte) 12, (byte)253, 
		(byte) 94, (byte)117, (byte)129, (byte)250, (byte) 81, (byte) 44, (byte)143, (byte) 73, 
		(byte) 97, (byte)169, (byte)235, (byte) 11, (byte)128, (byte)248, (byte)168, (byte)  7,
		(byte) 70, (byte)114, (byte)138, (byte) 85, (byte)255, (byte) 70, (byte) 71, (byte) 31, 

		(byte) 52, (byte) 37, (byte)6,   (byte) 59, (byte)157, (byte) 83, (byte)100, (byte) 47, 
		(byte) 94, (byte)222, (byte) 30, (byte)132, (byte)214, (byte) 19, (byte)  8, (byte) 26, 
		(byte)250, (byte) 92, (byte) 34, (byte)208, (byte) 81, (byte) 40, (byte) 91, (byte)214, 
		(byte) 59, (byte)148, (byte) 59, (byte) 86, (byte) 93, (byte)137, (byte)138, (byte)  5, 
		(byte)104, (byte) 84, (byte) 19, (byte)229, (byte) 60, (byte) 60, (byte)108, (byte)101, 

		(byte) 37, (byte)255, (byte) 31, (byte)227, (byte) 78, (byte) 61, (byte)220, (byte)112, 
		(byte)240, (byte)213, (byte)100, (byte) 80, (byte)253, (byte)164, (byte)139, (byte)161, 
		(byte) 46, (byte) 16, (byte) 78, (byte)157, (byte)235, (byte)159, (byte)184, (byte) 24,
		(byte)129, (byte)225, (byte)196, (byte)189, (byte)242, (byte) 93, (byte)146, (byte) 71, 
		(byte)244, (byte) 80, (byte)200, (byte)101, (byte)146, (byte)121, (byte)104, (byte)231, 

		(byte)115, (byte) 52, (byte)244, (byte) 65, (byte) 79, (byte)117, (byte)167, (byte) 80, 
		(byte)225, (byte) 57, (byte) 84, (byte)110, (byte) 58, (byte)138, (byte)115, (byte)157 };


	private static RSAPublicKey PUBLIC_KEY;


	private static RSAPrivateKey PRIVATE_KEY;


	static {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, MOD), new BigInteger(1, EXP));
			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, MOD), new BigInteger(1, MOD_PRIV));

			PUBLIC_KEY = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			PRIVATE_KEY = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

		} catch (Exception e) {

			System.err.println(e);
		}
	}


	private static final Base64URL B64_HEADER = new Base64URL("eyJhbGciOiJSUzI1NiJ9");


	private static final Payload PAYLOAD = new Payload(new Base64URL(
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));


	private static final byte[] SIGNABLE = ("eyJhbGciOiJSUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();


	private static final Base64URL B64_SIG = new Base64URL(
		"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
		"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
		"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
		"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
		"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
		"p0igcN_IoypGlUPQGe77Rw");


	public void testSupportedAlgorithms() {

		RSASSASigner signer = new RSASSASigner(PRIVATE_KEY);

		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS512));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.PS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.PS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.PS512));
		assertEquals(6, signer.supportedAlgorithms().size());

		RSASSAVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.RS256));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.RS384));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.RS512));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.PS256));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.PS384));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.PS512));
		assertEquals(6, verifier.supportedAlgorithms().size());
	}


	public void testGetAcceptedAlgorithms() {

		RSASSAVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.RS256));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.RS384));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.RS512));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.PS256));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.PS384));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.PS512));
		assertEquals(6, verifier.supportedAlgorithms().size());
	}


	public void testSetAcceptedAlgorithms() {

		RSASSAVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		try {
			verifier.setAcceptedAlgorithms(null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			verifier.setAcceptedAlgorithms(new HashSet<JWSAlgorithm>(Arrays.asList(JWSAlgorithm.ES256)));
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		verifier.setAcceptedAlgorithms(new HashSet<JWSAlgorithm>(Arrays.asList(JWSAlgorithm.RS256)));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.RS256));
		assertEquals(1, verifier.getAcceptedAlgorithms().size());
	}


	public void testSignAndVerify()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		assertEquals("RS256 alg check", JWSAlgorithm.RS256, header.getAlgorithm());

		JWSObject jwsObject = new JWSObject(header, PAYLOAD);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


		RSASSASigner signer = new RSASSASigner(PRIVATE_KEY);
		assertNotNull("Private key check", signer.getPrivateKey());

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


		RSASSAVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);
		assertNotNull("Public key check", verifier.getPublicKey());

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testSignWithReadyVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		JWSSigner signer = new RSASSASigner(PRIVATE_KEY);

		Base64URL b64sigComputed = signer.sign(header, SIGNABLE);

		assertEquals("Signature check", B64_SIG, b64sigComputed);
	}


	public void testVerifyWithReadyVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		JWSVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		boolean verified = verifier.verify(header, SIGNABLE, B64_SIG);

		assertTrue("Signature check", verified);
	}


	public void testParseAndVerify()
		throws Exception {

		String s = B64_HEADER.toString() + "." + PAYLOAD.toBase64URL().toString() + "." + B64_SIG.toString();

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Signature check", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testVerifyTruncatedSignature()
		throws Exception {

		String s = B64_HEADER.toString() + "." + PAYLOAD.toBase64URL().toString() + "." + B64_SIG.toString().substring(0, 100);

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		boolean verified = jwsObject.verify(verifier);

		assertFalse("Signature check", verified);
	}


	public static String transpose(String s) {
		int L = s.length();
		return (L < 2) ? s : s.substring(0, 1) + s.substring(L-1, L) + transpose(s.substring(1, L-1));
	}


	public void testVerifyBadSignatureOfExpectedLength()
		throws Exception {

		String s = B64_HEADER.toString() + "." + PAYLOAD.toBase64URL().toString() + "." + transpose(B64_SIG.toString());

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier = new RSASSAVerifier(PUBLIC_KEY);

		boolean verified = jwsObject.verify(verifier);

		assertFalse("Signature check", verified);
	}


	public void testRSASSASignAndVerifyCycle()
		throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		// Need BouncyCastle for PSS
		Security.addProvider(BouncyCastleProviderSingleton.getInstance());

		RSASSASigner signer = new RSASSASigner(privateKey);
		assertNotNull("Private key check", signer.getPrivateKey());

		RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
		assertNotNull("Public key check", verifier.getPublicKey());

		testSignAndVerifyCycle(JWSAlgorithm.RS256, signer, verifier);
		testSignAndVerifyCycle(JWSAlgorithm.RS384, signer, verifier);
		testSignAndVerifyCycle(JWSAlgorithm.RS512, signer, verifier);
	}


	public void testPSSSignAndVerifyCycle()
		throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		// Need BouncyCastle for PSS
		Security.addProvider(BouncyCastleProviderSingleton.getInstance());

		RSASSASigner signer = new RSASSASigner(privateKey);
		assertNotNull("Private key check", signer.getPrivateKey());

		RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
		assertNotNull("Public key check", verifier.getPublicKey());

		testSignAndVerifyCycle(JWSAlgorithm.PS256, signer, verifier);
		testSignAndVerifyCycle(JWSAlgorithm.PS384, signer, verifier);
		testSignAndVerifyCycle(JWSAlgorithm.PS512, signer, verifier);
	}


	public void testSignAndVerifyCycle(final JWSAlgorithm alg, final JWSSigner signer, final JWSVerifier verifier)
		throws Exception {

		JWSHeader header = new JWSHeader(alg);

		JWSObject jwsObject = new JWSObject(header, PAYLOAD);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		assertTrue("Verify signature", jwsObject.verify(verifier));

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());

		// Verify from serialised and then parsed JWS
		jwsObject = JWSObject.parse(jwsObject.serialize());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		assertTrue("Verify signature", jwsObject.verify(verifier));

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testExample()
		throws Exception {

		// RSA signatures require a public and private RSA key pair,
		// the public key must be made known to the JWS recipient in
		// order to verify the signatures
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		keyGenerator.initialize(1024);

		KeyPair kp = keyGenerator.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(privateKey);

		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("In RSA we trust!"));

		// Compute the RSA signature
		jwsObject.sign(signer);

		assertTrue(jwsObject.getState().equals(JWSObject.State.SIGNED));

		// To serialize to compact form, produces something like
		// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
		// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
		// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
		// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
		String s = jwsObject.serialize();

		// To parse the JWS and verify it, e.g. on client-side
		jwsObject = JWSObject.parse(s);

		JWSVerifier verifier = new RSASSAVerifier(publicKey);

		assertTrue(jwsObject.verify(verifier));

		assertEquals("In RSA we trust!", jwsObject.getPayload().toString());
	}


	public void testCompareSignatureFromRawKeyAndJWK()
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

		// Create signer from raw Java RSA key
		JWSObject jwsObject1 = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("test123"));
		JWSSigner signer = new RSASSASigner(rsaPrivateKey);
		jwsObject1.sign(signer);
		Base64URL sig1 = jwsObject1.getSignature();

		// Create signer from JWK representation
		RSAKey rsaJWK = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

		JWSObject jwsObject2 = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("test123"));
		signer = new RSASSASigner(rsaJWK.toRSAPrivateKey());
		jwsObject2.sign(signer);
		Base64URL sig2 = jwsObject2.getSignature();

		assertTrue("Signature comparison", sig1.equals(sig2));

		// Verifier from raw Java RSA key
		JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
		assertTrue(jwsObject1.verify(verifier));
		assertTrue(jwsObject2.verify(verifier));

		// Verifier from JWK representation
		verifier = new RSASSAVerifier(rsaJWK.toRSAPublicKey());
		assertTrue(jwsObject1.verify(verifier));
		assertTrue(jwsObject2.verify(verifier));
	}
}
