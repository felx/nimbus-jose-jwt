package com.nimbusds.jose.jwk;


import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the EC JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-22)
 */
public class ECKeyTest extends TestCase {


	// Test parameters are from JWK spec
	private static final class ExampleKeyP256 {

		public static final ECKey.Curve CRV = ECKey.Curve.P_256;
		public static final Base64URL X = new Base64URL("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
		public static final Base64URL Y = new Base64URL("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
		public static final Base64URL D = new Base64URL("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP256Alt {

		public static final ECKey.Curve CRV = ECKey.Curve.P_256;
		public static final Base64URL X = new Base64URL("3l2Da_flYc-AuUTm2QzxgyvJxYM_2TeB9DMlwz7j1PE");
		public static final Base64URL Y = new Base64URL("-kjT7Wrfhwsi9SG6H4UXiyUiVE9GHCLauslksZ3-_t0");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP384Alt {

		public static final ECKey.Curve CRV = ECKey.Curve.P_384;
		public static final Base64URL X = new Base64URL("Xy0mn0LmRyDBeHBjZrqH9z5Weu5pzCZYl1FJGHdoEj1utAoCpD4-Wn3VAIT-qgFF");
		public static final Base64URL Y = new Base64URL("mrZQ1aB1E7JksXe6LXmM3BiGzqtlwCtMN0cpJb5EU62JMSISSK8l7cXSFt84A25z");
	}


	// Test parameters are from Anders Rundgren, public only
	private static final class ExampleKeyP521Alt {

		public static final ECKey.Curve CRV = ECKey.Curve.P_521;
		public static final Base64URL X = new Base64URL("AfwEaSkqoPQynn4SdAXOqbyDuK6KsbI04i-6aWvh3GdvREZuHaWFyg791gcvJ4OqG13-gzfYxZxfblPMqfOtQrzk");
		public static final Base64URL Y = new Base64URL("AHgOZhhJb2ZiozkquiEa0Z9SfERJbWaaE7qEnCuk9VVZaWruKWKNzZadoIRPt8h305r14KRoxu8AfV20X-d_2Ups");
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


	public void testFullConstructorAndSerialization()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = null;

		ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
			              KeyUse.SIGNATURE, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5c);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testFullConstructorAndSerializationWithOps()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		KeyUse use = null;
		Set<KeyOperation> ops = new LinkedHashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
			use, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5c);

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testBuilder()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		ECKey key = new ECKey.Builder(ECKey.Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y).
			d(ExampleKeyP256.D).
			keyUse(KeyUse.SIGNATURE).
			algorithm(JWSAlgorithm.ES256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
		        build();
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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

		assertEquals(ECKey.Curve.P_256, key.getCurve());
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

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256.X, key.getX());
		assertEquals(ExampleKeyP256.Y, key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());

	}


	public void testP256ExportAndImport()
		throws Exception {

		// Public + private

		ECKey key = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).d(ExampleKeyP256.D).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP256.Y.decodeToBigInteger(), pub.getW().getAffineY());

		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		assertEquals(256, priv.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256.D.decodeToBigInteger(), priv.getS());

		// Import
		key = new ECKey.Builder(ECKey.Curve.P_256, pub).privateKey(priv).build();
		assertEquals(ECKey.Curve.P_256, key.getCurve());
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
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP256Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP256Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP256Alt.CRV, pub).build();
		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(ExampleKeyP256Alt.X, key.getX());
		assertEquals(ExampleKeyP256Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testP384AltExportAndImport()
		throws Exception {

		ECKey key = new ECKey.Builder(ExampleKeyP384Alt.CRV, ExampleKeyP384Alt.X, ExampleKeyP384Alt.Y).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(384, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP384Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP384Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP384Alt.CRV, pub).build();
		assertEquals(ECKey.Curve.P_384, key.getCurve());
		assertEquals(ExampleKeyP384Alt.X, key.getX());
		assertEquals(ExampleKeyP384Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testP521AltExportAndImport()
		throws Exception {

		ECKey key = new ECKey.Builder(ExampleKeyP521Alt.CRV, ExampleKeyP521Alt.X, ExampleKeyP521Alt.Y).build();

		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(521, pub.getParams().getCurve().getField().getFieldSize());
		assertEquals(ExampleKeyP521Alt.X.decodeToBigInteger(), pub.getW().getAffineX());
		assertEquals(ExampleKeyP521Alt.Y.decodeToBigInteger(), pub.getW().getAffineY());

		// Import
		key = new ECKey.Builder(ExampleKeyP521Alt.CRV, pub).build();
		assertEquals(ECKey.Curve.P_521, key.getCurve());
		assertEquals(ExampleKeyP521Alt.X, key.getX());
		assertEquals(ExampleKeyP521Alt.Y, key.getY());

		assertFalse(key.isPrivate());
	}


	public void testRejectKeyUseWithOps() {

		KeyUse use = KeyUse.SIGNATURE;

		Set<KeyOperation> ops = new HashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		try {
			new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, use, ops, null, null, null, null, null);

			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).
				keyUse(use).keyOperations(ops).build();
			fail();
		} catch (IllegalStateException e) {
			// ok
		}
	}
	
	
	public void testCookbookExampleKey()
		throws Exception {
		
		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.3.1
		
		String json = "{"+
			"\"kty\":\"EC\","+
			"\"kid\":\"bilbo.baggins@hobbiton.example\","+
			"\"use\":\"sig\","+
			"\"crv\":\"P-521\","+
			"\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"+
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","+
			"\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","+
			"\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"+
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""+
			"}";

		ECKey jwk = ECKey.parse(json);

		assertEquals(KeyType.EC, jwk.getKeyType());
		assertEquals("bilbo.baggins@hobbiton.example", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
		assertEquals(ECKey.Curve.P_521, jwk.getCurve());

		assertEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

		assertEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

		assertEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());

		// Convert to Java EC key object
		ECPublicKey ecPublicKey = jwk.toECPublicKey();
		ECPrivateKey ecPrivateKey = jwk.toECPrivateKey();

		jwk = new ECKey.Builder(ECKey.Curve.P_521, ecPublicKey).privateKey(ecPrivateKey).build();

		assertEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

		assertEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

		assertEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());
	}
}