package com.nimbusds.jwt;


import java.net.URI;
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


	public void testCustomClaimsAreOrderedByInsertion() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSetOne = new JWTClaimsSet();
		claimsSetOne = claimsSetOne.withSubject("alice");
		claimsSetOne = claimsSetOne.withIssueTime(new Date(123000l));
		claimsSetOne = claimsSetOne.withIssuer("https://c2id.com");
		claimsSetOne = claimsSetOne.withClaim("scope", "openid");

		JWSSigner signer = new RSASSASigner(privateKey);
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetOne);
		signedJWT.sign(signer);
		String orderOne = signedJWT.serialize();

		JWTClaimsSet claimsSetTwo = new JWTClaimsSet();
		claimsSetTwo = claimsSetTwo.withSubject("alice");
		claimsSetTwo = claimsSetTwo.withIssuer("https://c2id.com");
		claimsSetTwo = claimsSetTwo.withIssueTime(new Date(123000l));
		claimsSetTwo = claimsSetTwo.withClaim("scope", "openid");

		signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetTwo);
		signedJWT.sign(signer);
		String orderTwo = signedJWT.serialize();
		assertNotSame(orderOne, orderTwo);
	}

	public void testSignAndVerify()
		throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet = claimsSet.withSubject("alice");
		claimsSet = claimsSet.withIssueTime(new Date(123000l));
		claimsSet = claimsSet.withIssuer("https://c2id.com");
		claimsSet = claimsSet.withClaim("scope", "openid");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			jwkURL(new URI("https://c2id.com/jwks.json")).
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
