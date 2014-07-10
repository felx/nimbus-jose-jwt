package com.nimbusds.jwt;


import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests signed JWTs.
 */
public class SignedJWTTest extends TestCase {


	public void testSignAndVerify()
		throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date(123000l));
		claimsSet.setIssuer("https://c2id.com");
		claimsSet.setCustomClaim("scope", "openid");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			jwkURL(new URL("https://c2id.com/jwks.json")).
			build();

		SignedJWT signedJWT = new SignedJWT(header, claimsSet);

		assertEquals(JWSObject.State.UNSIGNED, signedJWT.getState());
		assertEquals(header, signedJWT.getHeader());
		assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
		assertEquals(123000l, signedJWT.getJWTClaimsSet().getIssueTime().getTime());
		assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
		assertEquals("openid", signedJWT.getJWTClaimsSet().getStringClaim("scope"));
		assertNull(signedJWT.getSignature());

		Base64URL sigInput = Base64URL.encode(signedJWT.getSigningInput());

		JWSSigner signer = new RSASSASigner(privateKey);

		signedJWT.sign(signer);

		assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
		assertNotNull(signedJWT.getSignature());

		String serializedJWT = signedJWT.serialize();

		signedJWT = SignedJWT.parse(serializedJWT);
		assertEquals(serializedJWT, signedJWT.getParsedString());

		assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
		assertNotNull(signedJWT.getSignature());
		assertTrue(sigInput.equals(Base64URL.encode(signedJWT.getSigningInput())));

		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		assertTrue(signedJWT.verify(verifier));
	}
}
