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


import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.junit.Assert;


/**
 * Tests the key converter.
 */
public class KeyConverterTest extends TestCase {


	private static final int COFACTOR = 1;


	public static final ECParameterSpec EC256SPEC = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
			new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")),
		new ECPoint(
			new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
			new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
		new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
		COFACTOR);
	

	public void testConvertNull() {

		assertTrue(KeyConverter.toJavaKeys(null).isEmpty());
	}


	public void testConvertEmpty() {

		assertTrue(KeyConverter.toJavaKeys(Collections.<JWK>emptyList()).isEmpty());
	}


	public void testConvertMixed()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.build();

		pairGen = KeyPairGenerator.getInstance("EC");
		pairGen.initialize(EC256SPEC);
		keyPair = pairGen.generateKeyPair();

		ECKey ecJWK = new ECKey.Builder(Curve.P_256, (ECPublicKey)keyPair.getPublic())
			.privateKey((ECPrivateKey)keyPair.getPrivate())
			.build();

		byte[] random = new byte[32];
		new SecureRandom().nextBytes(random);

		OctetSequenceKey octJWK = new OctetSequenceKey.Builder(random).build();

		List<JWK> jwkList = Arrays.asList(rsaJWK, ecJWK, octJWK);

		List<Key> outList = KeyConverter.toJavaKeys(jwkList);

		assertTrue(outList.get(0) instanceof RSAPublicKey);
		assertTrue(outList.get(1) instanceof RSAPrivateKey);
		assertTrue(outList.get(2) instanceof ECPublicKey);
		assertTrue(outList.get(3) instanceof ECPrivateKey);
		assertTrue(outList.get(4) instanceof SecretKey);

		Assert.assertArrayEquals(rsaJWK.toRSAPublicKey().getEncoded(), outList.get(0).getEncoded());
		Assert.assertArrayEquals(rsaJWK.toRSAPrivateKey().getEncoded(), outList.get(1).getEncoded());
		Assert.assertArrayEquals(ecJWK.toECPublicKey().getEncoded(), outList.get(2).getEncoded());
		Assert.assertArrayEquals(ecJWK.toECPrivateKey().getEncoded(), outList.get(3).getEncoded());
		Assert.assertArrayEquals(octJWK.toSecretKey().getEncoded(), outList.get(4).getEncoded());

		assertEquals(5, outList.size());
	}
}
