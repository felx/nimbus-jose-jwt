package com.nimbusds.jose.crypto;


import java.util.Collection;
import java.util.LinkedHashSet;

import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;


/**
 * Tests the algorithm support utility.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-20
 */
public class AlgorithmSupportMessageTest extends TestCase {


	public void testWithJWSAlgorithm() {

		JWSAlgorithm unsupported = JWSAlgorithm.ES256;

		Collection<JWSAlgorithm> supported = new LinkedHashSet<>();
		supported.add(JWSAlgorithm.HS256);

		String msg = AlgorithmSupportMessage.unsupportedJWSAlgorithm(unsupported, supported);

		assertEquals("Unsupported JWS algorithm ES256, must be HS256", msg);
	}


	public void testWithJWEAlgorithm() {

		JWEAlgorithm unsupported = JWEAlgorithm.A128GCMKW;

		Collection<JWEAlgorithm> supported = new LinkedHashSet<>();
		supported.add(JWEAlgorithm.RSA1_5);
		supported.add(JWEAlgorithm.RSA_OAEP);

		String msg = AlgorithmSupportMessage.unsupportedJWEAlgorithm(unsupported, supported);

		assertEquals("Unsupported JWE algorithm A128GCMKW, must be RSA1_5 or RSA-OAEP", msg);
	}


	public void testWithEncryptionMethod() {

		EncryptionMethod unsupported = EncryptionMethod.A128CBC_HS256_DEPRECATED;

		Collection<EncryptionMethod> supported = new LinkedHashSet<>();
		supported.add(EncryptionMethod.A128GCM);
		supported.add(EncryptionMethod.A192GCM);
		supported.add(EncryptionMethod.A256GCM);

		String msg = AlgorithmSupportMessage.unsupportedEncryptionMethod(unsupported, supported);

		assertEquals("Unsupported JWE encryption method A128CBC+HS256, must be A128GCM, A192GCM or A256GCM", msg);
	}


	public void testWithEllipticCurve() {

		ECKey.Curve unsupported = new ECKey.Curve("P-986");

		Collection<ECKey.Curve> supported = new LinkedHashSet<>();
		supported.add(ECKey.Curve.P_256);
		supported.add(ECKey.Curve.P_384);
		supported.add(ECKey.Curve.P_521);

		String msg = AlgorithmSupportMessage.unsupportedEllipticCurve(unsupported, supported);

		assertEquals("Unsupported elliptic curve P-986, must be P-256, P-384 or P-521", msg);
	}
}
