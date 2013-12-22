package com.nimbusds.jose.jwk;


import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the RSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-12-22)
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

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			                new Base64URL(p), new Base64URL(q), 
			                new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			                null,
			                Use.SIGNATURE, JWSAlgorithm.RS256, "1",
			                x5u, x5t, x5c);
		
		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
		

		// Test conversion to public JWK

		key = key.toPublicJWK();
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertNull(key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertFalse(key.isPrivate());
	}


	public void testBase64Builder()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		RSAKey key = new RSAKey.Builder(new Base64URL(n), new Base64URL(e)).
			privateExponent(new Base64URL(d)).
			firstPrimeFactor(new Base64URL(p)).
			secondPrimeFactor(new Base64URL(q)).
			firstFactorCRTExponent(new Base64URL(dp)).
			secondFactorCRTExponent(new Base64URL(dq)).
			firstCRTCoefficient(new Base64URL(qi)).
			keyUse(Use.SIGNATURE).
			algorithm(JWSAlgorithm.RS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}


	public void testObjectBuilder()
		throws Exception {

		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

		RSAKey key = new RSAKey.Builder(publicKey).
			privateKey(privateKey).
			keyUse(Use.SIGNATURE).
			algorithm(JWSAlgorithm.RS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertTrue(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger()));
		assertTrue(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger()));

		assertTrue(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger()));

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertTrue(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger()));
		assertTrue(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger()));

		assertTrue(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger()));

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}


	public void testPublicKeyExportAndImport()
		throws Exception {


		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e),
			                null, null, null,
			                null, null, null);

		// Public key export
		RSAPublicKey pubKey = key.toRSAPublicKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());


		// Public key import
		key = new RSAKey(pubKey, null, null, null, null, null, null);
		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());
	}


	public void testPrivateKeyExportAndImport()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			                new Base64URL(p), new Base64URL(q), 
			                new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			                null,
			                Use.SIGNATURE, JWSAlgorithm.RS256, "1",
			                null, null, null);

		// Private key export with CRT (2nd form)
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

		RSAPublicKey pubKey = (RSAPublicKey)pair.getPublic();
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


		// Key pair import, 1st private form
		key = new RSAKey(pubKey, privKey, Use.SIGNATURE, JWSAlgorithm.RS256, "1", null, null, null);
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		// Key pair import, 2nd private form
		key = new RSAKey(pubKey, privCrtKey, Use.SIGNATURE, JWSAlgorithm.RS256, "1", null, null, null);
		assertEquals(Use.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}


	public void testParseSomeKey()
		throws Exception {

		String json = "{\n" +
			"      \"kty\": \"RSA\",\n" +
			"      \"n\": \"f9BhJgBgoDKGcYLh+xl6qulS8fUFYxuWSz4Sk+7Yw2Wv4Wroe3yLzJjqEqH8IFR0Ow8Sr3pZo0IwOPcWHQZMQr0s2kWbKSpBrnDsK4vsdBvoP1jOaylA9XsHPF9EZ/1F+eQkVHoMsc9eccf0nmr3ubD56LjSorTsbOuxi8nqEzisvhDHthacW/qxbpR/jojQNfdWyDz6NC+MA2LYYpdsw5TG8AVdKjobHWfQvXYdcpvQRkDDhgbwQt1KD8ZJ1VL+nJcIfSppPzCbfM2eY78y/c4euL/SQPs7kGf+u3R9hden7FjMUuIFZoAictiBgjVZ/JOaK+C++L+IsnCKqauhEQ==\",\n" +
			"      \"e\": \"AQAB\",\n" +
			"      \"alg\": \"RS256\"\n" +
			"}";

		RSAKey key = RSAKey.parse(json);

		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());

		assertEquals(256, key.getModulus().decode().length);
	}
}