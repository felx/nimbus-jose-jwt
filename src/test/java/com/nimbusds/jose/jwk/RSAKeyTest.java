package com.nimbusds.jose.jwk;


import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import junit.framework.TestCase;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests RSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-20)
 */
public class RSAKeyTest extends TestCase {


	// Test parameters are from JPSK spec

	private static final String n = 
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
		"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
		"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
		"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
		"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";


	private static final String e = "AQAB";


	private static final String d = 
		"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
		"M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
		"wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
		"_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
		"nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
		"me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";


	private static final String p = 
		"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
		"nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
		"WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";


	private static final String q = 
		"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
		"qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
		"kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";


	private static final String dp = 
		"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
		"YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
		"YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";


	private static final String dq = 
		"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
		"vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
		"GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";


	private static final String qi =
		"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
		"UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
		"yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";


	public void testFullConstructorAndSerialization()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			                new Base64URL(p), new Base64URL(q), 
			                new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			                null,
			                Use.SIGNATURE, JWSAlgorithm.RS256, "1");
		
		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());
		

		// Test conversion to public JWK

		key = key.toPublicJWK();
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getExponent());

		assertNull(key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());
	}


	public void testKeyExport()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			                new Base64URL(p), new Base64URL(q), 
			                new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			                null,
			                Use.SIGNATURE, JWSAlgorithm.RS256, "1");

		// Public key export
		RSAPublicKey pubKey = key.toRSAPublicKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());


		// Private key export with CRT
		RSAPrivateKey privKey = key.toRSAPrivateKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), privKey.getModulus());
		assertEquals(new Base64URL(d).decodeToBigInteger(), privKey.getPrivateExponent());

		assertTrue(privKey instanceof RSAPrivateCrtKey);
		RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey)privKey;
		assertEquals(new Base64URL(e).decodeToBigInteger(), privCrtKey.getPublicExponent());
		assertEquals(new Base64URL(p).decodeToBigInteger(), privCrtKey.getPrimeP());
		assertEquals(new Base64URL(q).decodeToBigInteger(), privCrtKey.getPrimeQ());
		assertEquals(new Base64URL(dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
		assertEquals(new Base64URL(dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
		assertEquals(new Base64URL(qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());


		// Key pair export
		KeyPair pair = key.toKeyPair();

		pubKey = (RSAPublicKey)pair.getPublic();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());

		privKey = (RSAPrivateKey)pair.getPrivate();
		assertEquals(new Base64URL(n).decodeToBigInteger(), privKey.getModulus());
		assertEquals(new Base64URL(d).decodeToBigInteger(), privKey.getPrivateExponent());

		assertTrue(privKey instanceof RSAPrivateCrtKey);
		privCrtKey = (RSAPrivateCrtKey)privKey;
		assertEquals(new Base64URL(e).decodeToBigInteger(), privCrtKey.getPublicExponent());
		assertEquals(new Base64URL(p).decodeToBigInteger(), privCrtKey.getPrimeP());
		assertEquals(new Base64URL(q).decodeToBigInteger(), privCrtKey.getPrimeQ());
		assertEquals(new Base64URL(dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
		assertEquals(new Base64URL(dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
		assertEquals(new Base64URL(qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());
	}
}