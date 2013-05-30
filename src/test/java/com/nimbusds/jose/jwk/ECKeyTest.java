package com.nimbusds.jose.jwk;


import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the EC JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-30)
 */
public class ECKeyTest extends TestCase {


	// Test parameters are from JPSK spec

	private static final String x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";


	private static final String y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";


	private static final String d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";


	public void testFullConstructorAndSerialization()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		ECKey key = new ECKey(ECKey.Curve.P_256, new Base64URL(x), new Base64URL(y), new Base64URL(d),
			              Use.SIGNATURE, JWSAlgorithm.ES256, "1", x5u, x5t, x5c);
		
		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = ECKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());
		

		// Test conversion to public JWK

		key = key.toPublicJWK();
		
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}


	public void testBuilder()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		ECKey key = new ECKey.Builder(ECKey.Curve.P_256, new Base64URL(x), new Base64URL(y)).
		            setD(new Base64URL(d)).
		            setKeyUse(Use.SIGNATURE).
		            setAlgorithm(JWSAlgorithm.ES256).
		            setKeyID("1").
		            setX509CertURL(x5u).
		            setX509CertThumbprint(x5t).
		            setX509CertChain(x5c).
		            build();
		
		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = ECKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());
		

		// Test conversion to public JWK

		key = key.toPublicJWK();
		
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());

	}


	public void testP256ExportAndImport()
		throws Exception {


		ECKey key = new ECKey(ECKey.Curve.P_256, new Base64URL(x), new Base64URL(y), new Base64URL(d),
			              Use.SIGNATURE, JWSAlgorithm.ES256, "1", null, null, null);


		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(new Base64URL(x), Base64URL.encode(pub.getW().getAffineX()));
		assertEquals(new Base64URL(y), Base64URL.encode(pub.getW().getAffineY()));

		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		assertEquals(new Base64URL(d), Base64URL.encode(priv.getS()));


		// Import
		key = new ECKey(ECKey.Curve.P_256, pub, priv, Use.SIGNATURE, JWSAlgorithm.ES256, "1", null, null, null);
		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());
	}


	public void testP384ExportAndImport()
		throws Exception {


		ECKey key = new ECKey(ECKey.Curve.P_384, new Base64URL(x), new Base64URL(y), new Base64URL(d),
			              Use.SIGNATURE, JWSAlgorithm.ES384, "1", null, null, null);


		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(new Base64URL(x), Base64URL.encode(pub.getW().getAffineX()));
		assertEquals(new Base64URL(y), Base64URL.encode(pub.getW().getAffineY()));

		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		assertEquals(new Base64URL(d), Base64URL.encode(priv.getS()));


		// Import
		key = new ECKey(ECKey.Curve.P_384, pub, priv, Use.SIGNATURE, JWSAlgorithm.ES384, "1", null, null, null);
		assertEquals(ECKey.Curve.P_384, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());
	}


	public void testP521ExportAndImport()
		throws Exception {

		ECKey key = new ECKey(ECKey.Curve.P_521, new Base64URL(x), new Base64URL(y), new Base64URL(d),
			              Use.SIGNATURE, JWSAlgorithm.ES512, "1", null, null, null);


		// Export
		KeyPair pair = key.toKeyPair();

		ECPublicKey pub = (ECPublicKey)pair.getPublic();
		assertEquals(new Base64URL(x), Base64URL.encode(pub.getW().getAffineX()));
		assertEquals(new Base64URL(y), Base64URL.encode(pub.getW().getAffineY()));

		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		assertEquals(new Base64URL(d), Base64URL.encode(priv.getS()));


		// Import
		key = new ECKey(ECKey.Curve.P_521, pub, priv, Use.SIGNATURE, JWSAlgorithm.ES512, "1", null, null, null);
		assertEquals(ECKey.Curve.P_521, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertEquals(new Base64URL(d), key.getD());

		assertTrue(key.isPrivate());
	}
}