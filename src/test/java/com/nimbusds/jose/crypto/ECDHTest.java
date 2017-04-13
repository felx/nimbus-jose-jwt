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


import java.util.Arrays;
import javax.crypto.SecretKey;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Tests the ECDH key agreement derivation.
 *
 * @version 2017-04-13
 */
public class ECDHTest extends TestCase{


	public void testDerive256BitSecret()
		throws Exception {

		ECKey ecJWK = new ECKey.Builder(
			ECKey.Curve.P_256,
			new Base64URL("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
			new Base64URL("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")).
			d(new Base64URL("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")).
			build();

		SecretKey sharedSecret = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), ecJWK.toECPrivateKey(), null);
		assertEquals("AES", sharedSecret.getAlgorithm());

		assertEquals(256, sharedSecret.getEncoded().length * 8);

		// Repeat with BouncyCastle provider
		SecretKey sharedSecretCopy = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), ecJWK.toECPrivateKey(),
			BouncyCastleProviderSingleton.getInstance());

		// The algorithm is deterministic, the two outputs must be identical
		assertTrue(Arrays.equals(sharedSecret.getEncoded(), sharedSecretCopy.getEncoded()));
	}


	public void testDerive384BitSecret()
		throws Exception {

		ECKey ecJWK = new ECKey.Builder(
			ECKey.Curve.P_384,
			new Base64URL("fqxniq8aXNPh3kJE45IqV5ZZWk4a9kSt1n4rfX8ZcHFj3EoJ7uCYSrc1aojxBFOF"),
			new Base64URL("InYXxcXnfv_pcH5k31EC-Uengvd0bVuF0SJ6cbjs9UBiT1Ym2aaI0cyW54afjU-0"))
			.d(new Base64URL("hUdUjG8Bru5knbrULOI-aDhtyZumcbFb025gnDBfwEas-W7kpFao8IEqnQHeQDVH"))
			.build();

		SecretKey sharedSecret = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), ecJWK.toECPrivateKey(), null);

		assertEquals(384, sharedSecret.getEncoded().length * 8);
	}


	public void testDerive512BitSecret()
		throws Exception {

		ECKey ecJWK = new ECKey.Builder(
			ECKey.Curve.P_521,
			new Base64URL("Ab8rUh0gVFn_toNpPkSctd3yJ03JJuLVoHtECLGrAiNJQ1hWvEXPbjuWZ5lNchOSws-C5vWVCxiXHt88JTqIYB3g"),
			new Base64URL("ADDpbPJYw_eONxiCdcJmY39eBKNQCA_vRtqDTTK0nzXEXs63dx1Mswp1kUzDSFj4_Gwm30AyHYLZhD88yY9oW-5e"))
			.d(new Base64URL("ADO81GOJgx5lfUevC1Ps5NiqEtkT4qIp68rhQzfY2Fb0IKgG07qyBwt6peV7yab7vlgaf01XUgPQQY1_xm4EK7CB"))
			.build();

		SecretKey sharedSecret = ECDH.deriveSharedSecret(ecJWK.toECPublicKey(), ecJWK.toECPrivateKey(), null);

		assertEquals(528, sharedSecret.getEncoded().length * 8);
	}


	public void testSpecExample()
		throws Exception {
		// http://tools.ietf.org/html/rfc7518#appendix-C

		ECKey epk = ECKey.parse("{\"kty\":\"EC\"," +
			"\"crv\":\"P-256\"," +
			"\"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\"," +
			"\"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\"," +
			"\"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"" +
			"}");

		ECKey consumerKey = ECKey.parse("{\"kty\":\"EC\"," +
			"\"crv\":\"P-256\"," +
			"\"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\"," +
			"\"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\"," +
			"\"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"" +
			"}");

		SecretKey sharedSecret = ECDH.deriveSharedSecret(consumerKey.toECPublicKey(), epk.toECPrivateKey(), null);

		byte[] expected = {
			(byte)158, (byte) 86, (byte)217, (byte) 29, (byte)129, (byte)113, (byte) 53, (byte)211,
			(byte)114, (byte)131, (byte) 66, (byte)131, (byte)191, (byte)132, (byte) 38, (byte)156,
			(byte)251, (byte) 49, (byte)110, (byte)163, (byte)218, (byte)128, (byte)106, (byte) 72,
			(byte)246, (byte)218, (byte)167, (byte)121, (byte)140, (byte)254, (byte)144, (byte)196 };

		assertTrue(Arrays.equals(expected, sharedSecret.getEncoded()));
	}
}
