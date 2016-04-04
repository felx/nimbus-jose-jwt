package com.nimbusds.jose.crypto;


import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import junit.framework.TestCase;


/**
 * Tests the static ECDSA utilities.
 *
 * @version 2015-05-30
 */
public class ECDSATest extends TestCase {


	public void testResolveAlgFromCurve()
		throws JOSEException {

		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(ECKey.Curve.P_256));
		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(ECKey.Curve.P_384));
		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(ECKey.Curve.P_521));

		try {
			ECDSA.resolveAlgorithm((ECKey.Curve)null);

		} catch (JOSEException e) {
			assertEquals("The EC key curve is not supported, must be P256, P384 or P521", e.getMessage());
		}
	}


	public void testResolveAlgFromECKey_P256()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC256SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(privateKey));
	}


	public void testResolveAlgFromECKey_P384()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC384SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(privateKey));
	}


	public void testResolveAlgFromECKey_P521()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC512SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(privateKey));
	}
}
