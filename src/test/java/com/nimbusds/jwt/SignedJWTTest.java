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
import com.nimbusds.jose.util.base64.Base64URL;


/**
 * Tests signed JWTs.
 */
public class SignedJWTTest extends TestCase {


	public void testCustomClaimsAreOrderedByInsertion() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSetOne = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSSigner signer = new RSASSASigner(privateKey);
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetOne);
		signedJWT.sign(signer);
		String orderOne = signedJWT.serialize();

		JWTClaimsSet claimsSetTwo = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer("https://c2id.com")
			.issueTime(new Date(123000L))
			.claim("scope", "openid")
			.build();

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

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			jwkURL(new URI("https://c2id.com/jwks.json")).
			build();

		SignedJWT signedJWT = new SignedJWT(header, claimsSet);

		assertEquals(JWSObject.State.UNSIGNED, signedJWT.getState());
		assertEquals(header, signedJWT.getHeader());
		assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
		assertEquals(123000L, signedJWT.getJWTClaimsSet().getIssueTime().getTime());
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
