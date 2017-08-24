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


import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * Tests the EC JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-08-24
 */
public class ECKeyTest extends TestCase {


	// Test parameters are from JWK spec
	private static final class ExampleKeyP256 {


		public static final Curve CRV = Curve.P_256;


		public static final Base64URL X = new Base64URL("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");


		public static final Base64URL Y = new Base64URL("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");


		public static final Base64URL D = new Base64URL("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP256Alt {


		public static final Curve CRV = Curve.P_256;


		public static final Base64URL X = new Base64URL("3l2Da_flYc-AuUTm2QzxgyvJxYM_2TeB9DMlwz7j1PE");


		public static final Base64URL Y = new Base64URL("-kjT7Wrfhwsi9SG6H4UXiyUiVE9GHCLauslksZ3-_t0");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP384Alt {


		public static final Curve CRV = Curve.P_384;


		public static final Base64URL X = new Base64URL("Xy0mn0LmRyDBeHBjZrqH9z5Weu5pzCZYl1FJGHdoEj1utAoCpD4-Wn3VAIT-qgFF");


		public static final Base64URL Y = new Base64URL("mrZQ1aB1E7JksXe6LXmM3BiGzqtlwCtMN0cpJb5EU62JMSISSK8l7cXSFt84A25z");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP521Alt {
		
		
		public static final Curve CRV = Curve.P_521;
		
		
		public static final Base64URL X = new Base64URL("AfwEaSkqoPQynn4SdAXOqbyDuK6KsbI04i-6aWvh3GdvREZuHaWFyg791gcvJ4OqG13-gzfYxZxfblPMqfOtQrzk");
		
		
		public static final Base64URL Y = new Base64URL("AHgOZhhJb2ZiozkquiEa0Z9SfERJbWaaE7qEnCuk9VVZaWruKWKNzZadoIRPt8h305r14KRoxu8AfV20X-d_2Ups");
	}


	public void testKeySizes() {

		assertEquals(256, new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build().size());
		assertEquals(256, new ECKey.Builder(ExampleKeyP256Alt.CRV, ExampleKeyP256Alt.X, ExampleKeyP256Alt.Y).build().size());
		assertEquals(384, new ECKey.Builder(ExampleKeyP384Alt.CRV, ExampleKeyP384Alt.X, ExampleKeyP384Alt.Y).build().size());
		assertEquals(521, new ECKey.Builder(ExampleKeyP521Alt.CRV, ExampleKeyP521Alt.X, ExampleKeyP521Alt.Y).build().size());
	}


	public void testUnknownCurve() {

		try {
			new ECKey.Builder(new Curve("unknown"), ExampleKeyP256.X, ExampleKeyP256.Y).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Unknown / unsupported curve: unknown", e.getMessage());
		}
	}


	public void testAltECKeyParamLengths() {

		assertEquals(32, ExampleKeyP256Alt.X.decode().length);
		assertEquals(32, ExampleKeyP256Alt.Y.decode().length);

		assertEquals(48, ExampleKeyP384Alt.X.decode().length);
		assertEquals(48, ExampleKeyP384Alt.Y.decode().length);

		assertEquals(66, ExampleKeyP521Alt.X.decode().length);
		assertEquals(66, ExampleKeyP521Alt.Y.decode().length);
	}


	public void testCoordinateEncoding() {

		byte[] unpadded = {1, 2, 3, 4, 5};
		BigInteger bigInteger = new BigInteger(1, unpadded);

		// With no padding required
		int fieldSize = unpadded.length * 8;
		assertEquals(Base64URL.encode(unpadded), ECKey.encodeCoordinate(fieldSize, bigInteger));

		// With two leading zeros padding required
		fieldSize = unpadded.length * 8 + 2 * 8;
		assertEquals(Base64URL.encode(new byte[]{0, 0, 1, 2, 3, 4, 5}), ECKey.encodeCoordinate(fieldSize, bigInteger));
		assertEquals(bigInteger.toString(), ECKey.encodeCoordinate(fieldSize, bigInteger).decodeToBigInteger().toString());
	}


	public void testFullPrivateConstructorAndSerialization()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = null;
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
			KeyUse.SIGNATURE, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5t256, x5c, keyStore);

		assertTrue(key instanceof AssymetricJWK);
		assertTrue(key instanceof CurveBasedJWK);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = ECKey.parse(jwkString);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		// Test conversion to public JWK

		key = key.toPublicJWK();

		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testPrivateConstructorAndSerializationWithOps()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));

		KeyUse use = null;
		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
			use, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5t256, x5c, null);

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = ECKey.parse(jwkString);

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		// Test conversion to public JWK

		key = key.toPublicJWK();

		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testBuilder()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		ECKey key = new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
			.d(ExampleKeyP256.D)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.ES256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = ECKey.parse(jwkString);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());


		// Test conversion to public JWK

		key = key.toPublicJWK();

		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testCopyBuilder()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		ECKey key = new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
			.d(ExampleKeyP256.D)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.ES256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();
		
		// Copy
		key = new ECKey.Builder(key).build();

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());

		assertTrue(key.isPrivate());
	}


	public void testP256ExportAndImport()
		throws Exception {

		// Public + private

		ECKey key = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).d(ExampleKeyP256.D).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey) pair.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP256.Y.decodeToBigInteger(), pub.getW().getAffineY());

		ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();
		assertEquals(256, priv.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256.D.decodeToBigInteger(), priv.getS());

		// Import
		key = new ECKey.Builder(Curve.P_256, pub).privateKey(priv).build();
		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertEquals(ExampleKeyP256.D, key.getD());
		assertEquals(32, ExampleKeyP256.D.decode().length);

		assertTrue(key.isPrivate());
	}


	public void testP256AltExportAndImport()
		throws Exception {

		ECKey key = new ECKey.Builder(ExampleKeyP256Alt.CRV, ExampleKeyP256Alt.X, ExampleKeyP256Alt.Y).build();

		// Export
		KeyPair pair = key.toKeyPair(BouncyCastleProviderSingleton.getInstance());

		ECPublicKey pub = (ECPublicKey) pair.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP256Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP256Alt.CRV, pub).build();
		assertEquals(Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256Alt.X, key.getX());
		assertEquals(ExampleKeyP256Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testP384AltExportAndImport()
		throws Exception {

		ECKey key = new ECKey.Builder(ExampleKeyP384Alt.CRV, ExampleKeyP384Alt.X, ExampleKeyP384Alt.Y).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey) pair.getPublic();
		assertEquals(384, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP384Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP384Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP384Alt.CRV, pub).build();
		assertEquals(Curve.P_384, key.getCurve());
		assertEquals(ExampleKeyP384Alt.X, key.getX());
		assertEquals(ExampleKeyP384Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testP521AltExportAndImport()
		throws Exception {

		ECKey key = new ECKey.Builder(ExampleKeyP521Alt.CRV, ExampleKeyP521Alt.X, ExampleKeyP521Alt.Y).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey) pair.getPublic();
		assertEquals(521, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP521Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP521Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP521Alt.CRV, pub).build();
		assertEquals(Curve.P_521, key.getCurve());
		assertEquals(ExampleKeyP521Alt.X, key.getX());
		assertEquals(ExampleKeyP521Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testKeyUseConsistentWithOps() {

		KeyUse use = KeyUse.SIGNATURE;

		Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		JWK jwk = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, use, ops, null, null, null, null, null, null, null);
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
		
		jwk = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
			.keyUse(use)
			.keyOperations(ops)
			.build();
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
	}
	
	
	public void testRejectKeyUseNotConsistentWithOps() {
		
		KeyUse use = KeyUse.SIGNATURE;
		
		Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT));
		
		try {
			new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
				.keyUse(use)
				.keyOperations(ops)
				.build();
		} catch (IllegalStateException e) {
			assertEquals("The key use \"use\" and key options \"key_opts\" parameters are not consistent, see RFC 7517, section 4.3", e.getMessage());
		}
	}


	public void testCookbookExampleKey()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-3.2

		String json = "{" +
			"\"kty\":\"EC\"," +
			"\"kid\":\"bilbo.baggins@hobbiton.example\"," +
			"\"use\":\"sig\"," +
			"\"crv\":\"P-521\"," +
			"\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\"," +
			"\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\"," +
			"\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\"" +
			"}";

		ECKey jwk = ECKey.parse(json);

		assertEquals(KeyType.EC, jwk.getKeyType());
		assertEquals("bilbo.baggins@hobbiton.example", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
		assertEquals(Curve.P_521, jwk.getCurve());

		assertEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

		assertEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

		assertEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());

		// Convert to Java EC key object
		ECPublicKey ecPublicKey = jwk.toECPublicKey();
		ECPrivateKey ecPrivateKey = jwk.toECPrivateKey();

		jwk = new ECKey.Builder(Curve.P_521, ecPublicKey).privateKey(ecPrivateKey).build();

		assertEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

		assertEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

		assertEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());
	}


	public void testThumbprint()
		throws Exception {

		ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build();

		Base64URL thumbprint = ecKey.computeThumbprint();

		assertEquals(256 / 8, thumbprint.decode().length);

		String orderedJSON = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";

		Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(Charset.forName("UTF-8"))));

		assertEquals(expected, thumbprint);
	}


	public void testThumbprintSHA1()
		throws Exception {

		ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build();

		Base64URL thumbprint = ecKey.computeThumbprint("SHA-1");

		assertEquals(160 / 8, thumbprint.decode().length);
	}


	public void testThumbprintAsKeyID()
		throws Exception {

		ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
			.keyIDFromThumbprint()
			.build();

		Base64URL thumbprint = new Base64URL(ecKey.getKeyID());

		assertEquals(256 / 8, thumbprint.decode().length);

		String orderedJSON = JSONObject.toJSONString(ecKey.getRequiredParams());

		Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(Charset.forName("UTF-8"))));

		assertEquals(expected, thumbprint);
	}


	public void testThumbprintSHA1AsKeyID()
		throws Exception {

		ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
			.keyIDFromThumbprint("SHA-1")
			.build();

		Base64URL thumbprint = new Base64URL(ecKey.getKeyID());

		assertEquals(160 / 8, thumbprint.decode().length);
	}


	// See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
	public void testJose4jVectorP256()
		throws Exception {

		String json = "{\"kty\":\"EC\"," +
			"\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
			"\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
			"\"crv\":\"P-256\"}";

		ECKey ecKey = ECKey.parse(json);

		assertEquals("j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs", ecKey.computeThumbprint().toString());
	}


	// See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
	public void testJose4jVectorP384()
		throws Exception {

		String json = "{\"kty\":\"EC\"," +
			" \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\"," +
			" \"y\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\"," +
			" \"crv\":\"P-384\"}";

		ECKey ecKey = ECKey.parse(json);

		assertEquals("vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM", ecKey.computeThumbprint().toString());
	}


	// See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
	public void testJose4jVectorP521()
		throws Exception {

		String json = "{\"kty\":\"EC\"," +
			"\"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId88hTyHgq180JDt\"," +
			"\"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS42trhDTu\"," +
			"\"crv\":\"P-521\"}";

		ECKey ecKey = ECKey.parse(json);

		assertEquals("rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg", ecKey.computeThumbprint().toString());
	}
	
	
	// For private EC keys as PKCS#11 handle
	public void testPrivateKeyHandle()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(Curve.P_256.toECParameterSpec());
		KeyPair kp = gen.generateKeyPair();
		
		ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
		PrivateKey privateKey = kp.getPrivate(); // simulate private key with inaccessible key material
		
		ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey)
			.privateKey(privateKey)
			.keyID("1")
			.build();
		
		assertNotNull(ecJWK.toPublicKey());
		assertEquals(privateKey, ecJWK.toPrivateKey());
		assertTrue(ecJWK.isPrivate());
		
		kp = ecJWK.toKeyPair();
		assertNotNull(kp.getPublic());
		assertEquals(privateKey, kp.getPrivate());
		
		JSONObject json = ecJWK.toJSONObject();
		assertEquals("EC", json.get("kty"));
		assertEquals("1", json.get("kid"));
		assertEquals("P-256", json.get("crv"));
		assertNotNull(json.get("x"));
		assertNotNull(json.get("y"));
		assertEquals(5, json.size());
	}
	
	
	public void testParseFromX509Cert()
		throws Exception {
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		ECKey ecKey = ECKey.parse(cert);
		
		assertEquals(KeyType.EC, ecKey.getKeyType());
		assertEquals(Curve.P_256, ecKey.getCurve());
		assertEquals(KeyUse.ENCRYPTION, ecKey.getKeyUse());
		assertEquals(cert.getSerialNumber().toString(10), ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertEquals(Base64URL.encode(sha256.digest(cert.getEncoded())), ecKey.getX509CertSHA256Thumbprint());
		assertNull(ecKey.getAlgorithm());
		assertNull(ecKey.getKeyOperations());
	}
	
	
	public void testParseFromX509CertWithRSAPublicKey()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		try {
			ECKey.parse(cert);
			fail();
		} catch (JOSEException e) {
			assertEquals("The public key of the X.509 certificate is not EC", e.getMessage());
		}
	}
	
	
	public void testLoadFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(Curve.P_521.toECParameterSpec());
		KeyPair kp = gen.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey)kp.getPrivate();
		
		// Generate certificate
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new java.security.cert.Certificate[]{cert});
		
		// Load
		ECKey ecKey = ECKey.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(ecKey);
		assertEquals(Curve.P_521, ecKey.getCurve());
		assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
		assertEquals("1", ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertNotNull(ecKey.getX509CertSHA256Thumbprint());
		assertTrue(ecKey.isPrivate());
		assertEquals(keyStore, ecKey.getKeyStore());
		
		// Try to load with bad pin
		try {
			ECKey.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't retrieve private EC key (bad pin?): Cannot recover key", e.getMessage());
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadFromKeyStore_publicKeyOnly()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		keyStore.setCertificateEntry("1", cert);
		
		ECKey ecKey = ECKey.load(keyStore, "1", null);
		assertNotNull(ecKey);
		assertEquals(Curve.P_256, ecKey.getCurve());
		assertEquals(KeyUse.ENCRYPTION, ecKey.getKeyUse());
		assertEquals("1", ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertNotNull(ecKey.getX509CertSHA256Thumbprint());
		assertFalse(ecKey.isPrivate());
		assertEquals(keyStore, ecKey.getKeyStore());
	}
	
	
	public void testLoadFromKeyStore_notEC()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		keyStore.setCertificateEntry("1", cert);
		
		try {
			ECKey.load(keyStore, "1", null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't load EC JWK: The key algorithm is not EC", e.getMessage());
		}
	}
	
	
	public void testLoadFromKeyStore_notFound()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		assertNull(ECKey.load(keyStore, "1", null));
	}
	
	
	// iss #217
	public void testEnsurePublicXYCoordinatesOnCurve()
		throws Exception {
		
		try {
			new ECKey(
				Curve.P_256,
				ExampleKeyP384Alt.X, // on diff curve
				ExampleKeyP384Alt.Y, // on diff curve
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
		}
		
		try {
			new ECKey(
				Curve.P_256,
				ExampleKeyP384Alt.X, // on diff curve
				ExampleKeyP384Alt.Y, // on diff curve
				ExampleKeyP256.D,    // private D coordinate
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
		}
	}
	
	
	// iss #217
	public void testCurveMismatch()
		throws Exception {
		
		// EC key on P_256
		ECParameterSpec ecParameterSpec = Curve.P_256.toECParameterSpec();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();
		ECKey ecJWK_p256 = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
			.privateKey((ECPrivateKey) keyPair.getPrivate())
			.build();
		
		// EC key on P_384
		ecParameterSpec = Curve.P_384.toECParameterSpec();
		generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		keyPair = generator.generateKeyPair();
		ECKey ecJWK_p384 = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic())
			.privateKey((ECPrivateKey) keyPair.getPrivate())
			.build();
		
		
		// Try to create EC key with P_256 params, but with x and y from P_384 curve key
		
		ECPoint w = new ECPoint(ecJWK_p384.getX().decodeToBigInteger(), ecJWK_p384.getY().decodeToBigInteger());
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, Curve.P_256.toECParameterSpec());
		
		// Default Sun provider
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			keyFactory.generatePublic(publicKeySpec);
			fail();
		} catch (RuntimeException e) {
			assertEquals("Point coordinates do not match field size", e.getMessage());
		}
		
		// BouncyCastle provider
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
			keyFactory.generatePublic(publicKeySpec);
			fail();
		} catch (InvalidKeySpecException e) {
			assertEquals("invalid KeySpec: x value invalid for SecP256R1FieldElement", e.getMessage());
		}
	}
}