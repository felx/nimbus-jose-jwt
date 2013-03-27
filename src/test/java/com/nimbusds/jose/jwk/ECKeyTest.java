package com.nimbusds.jose.jwk;


import java.util.Enumeration;

import junit.framework.TestCase;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the EC JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-27)
 */
public class ECKeyTest extends TestCase {


	// Test parameters are from JPSK spec

	private static final String x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";


	private static final String y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";


	private static final String d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";


	public void testCurveLookup()
		throws Exception {

		System.out.print("Named ECC curves: ");

		Enumeration names = ECNamedCurveTable.getNames();

		while (names.hasMoreElements()) {

			System.out.print(names.nextElement() + " ");
		}
	}


	public void testFullConstructorAndSerialization()
		throws Exception {

		ECKey key = new ECKey(ECKey.Curve.P_256, new Base64URL(x), new Base64URL(y), new Base64URL(d),
			              Use.SIGNATURE, JWSAlgorithm.ES256, "1");
		
		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.ES256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

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

		assertEquals(ECKey.Curve.P_256, key.getCurve());
		assertEquals(new Base64URL(x), key.getX());
		assertEquals(new Base64URL(y), key.getY());
		assertNull(key.getD());

		assertFalse(key.isPrivate());
	}
}