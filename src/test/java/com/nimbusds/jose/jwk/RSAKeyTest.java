package com.nimbusds.jose.jwk;


import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the RSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-21)
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
			                KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
			                x5u, x5t, x5c);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
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
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
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
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
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
			keyUse(KeyUse.SIGNATURE).
			algorithm(JWSAlgorithm.RS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
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
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
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

		Set<KeyOperation> ops = new LinkedHashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

		RSAKey key = new RSAKey.Builder(publicKey).
			privateKey(privateKey).
			keyUse(null).
			keyOperations(ops).
			algorithm(JWSAlgorithm.RS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
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
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
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
			                null, null, null, null,
			                null, null, null);

		// Public key export
		RSAPublicKey pubKey = key.toRSAPublicKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());


		// Public key import
		key = new RSAKey(pubKey, null, null, null, null, null, null, null);
		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());
	}


	public void testPrivateKeyExportAndImport()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			                new Base64URL(p), new Base64URL(q), 
			                new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			                null,
			                KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
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
		key = new RSAKey(pubKey, privKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null);
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
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
		key = new RSAKey(pubKey, privCrtKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null);
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
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


	public void testKeyConversionRoundTrip()
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey rsaPublicKeyIn = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKeyIn = (RSAPrivateKey)keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey.Builder(rsaPublicKeyIn).privateKey(rsaPrivateKeyIn).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK.getPrivateExponent().decodeToBigInteger());

		// Convert back to Java RSA keys
		RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
		RSAPrivateKey rsaPrivateKeyOut = rsaJWK.toRSAPrivateKey();

		assertEquals(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaPublicKeyOut.getPublicExponent());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaPublicKeyOut.getModulus());

		assertEquals(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaPrivateKeyOut.getPrivateExponent());

		// Compare encoded forms
		assertEquals("Public RSA", Base64.encode(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
		assertEquals("Private RSA", Base64.encode(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());

		RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK2.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK2.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK2.getPrivateExponent().decodeToBigInteger());
	}


	public void testKeyConversionRoundTripWithCRTParams()
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey rsaPublicKeyIn = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateCrtKey rsaPrivateKeyIn = (RSAPrivateCrtKey)keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey(rsaPublicKeyIn, rsaPrivateKeyIn, null, null, null, null, null, null, null);

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK.getPrivateExponent().decodeToBigInteger());

		// Compare CRT params
		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaJWK.getFirstPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaJWK.getSecondPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK.getFirstFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK.getSecondFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK.getFirstCRTCoefficient().decodeToBigInteger());
		assertTrue(rsaJWK.getOtherPrimes() == null || rsaJWK.getOtherPrimes().isEmpty());

		// Convert back to Java RSA keys
		RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
		RSAPrivateCrtKey rsaPrivateKeyOut = (RSAPrivateCrtKey)rsaJWK.toRSAPrivateKey();

		assertEquals(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaPublicKeyOut.getPublicExponent());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaPublicKeyOut.getModulus());

		assertEquals(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaPrivateKeyOut.getPrivateExponent());

		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaPrivateKeyOut.getPrimeP());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaPrivateKeyOut.getPrimeQ());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaPrivateKeyOut.getPrimeExponentP());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaPrivateKeyOut.getPrimeExponentQ());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaPrivateKeyOut.getCrtCoefficient());

		// Compare encoded forms
		assertEquals("Public RSA", Base64.encode(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
		assertEquals("Private RSA", Base64.encode(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());

		RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK2.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK2.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK2.getPrivateExponent().decodeToBigInteger());

		// Compare CRT params
		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaJWK2.getFirstPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaJWK2.getSecondPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK2.getFirstFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK2.getSecondFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK2.getFirstCRTCoefficient().decodeToBigInteger());
		assertTrue(rsaJWK2.getOtherPrimes() == null || rsaJWK2.getOtherPrimes().isEmpty());
	}


	public void testRejectKeyUseWithOps() {

		KeyUse use = KeyUse.SIGNATURE;

		Set<KeyOperation> ops = new HashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		try {
			new RSAKey(new Base64URL(n), new Base64URL(e), use, ops, null, null, null, null, null);

			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			new RSAKey.Builder(new Base64URL(n), new Base64URL(e)).
				keyUse(use).keyOperations(ops).build();
			fail();
		} catch (IllegalStateException e) {
			// ok
		}
	}


	public void testParseCookbookExample()
		throws Exception {

		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.1.1

		String json = "{" +
			"\"kty\": \"RSA\"," +
			"\"kid\": \"bilbo.baggins@hobbiton.example\"," +
			"\"use\": \"sig\"," +
			"\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw\"," +
			"\"e\": \"AQAB\"," +
			"\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ\"," +
			"\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
			"aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
			"peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
			"bUq0k\"," +
			"\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
			"8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
			"V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
			"s7pFc\"," +
			"\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
			"1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
			"-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
			"59ehik\"," +
			"\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
			"AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
			"bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
			"T1cYF8\"," +
			"\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
			"ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
			"jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
			"z8aaI4\"" +
			"}";

		RSAKey jwk = RSAKey.parse(json);

		assertEquals(KeyType.RSA, jwk.getKeyType());
		assertEquals("bilbo.baggins@hobbiton.example", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());

		assertEquals("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ", jwk.getPrivateExponent().toString());

		assertEquals("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
			"aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
			"peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
			"bUq0k", jwk.getFirstPrimeFactor().toString());

		assertEquals("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
			"8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
			"V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
			"s7pFc", jwk.getSecondPrimeFactor().toString());

		assertEquals("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
			"1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
			"-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
			"59ehik", jwk.getFirstFactorCRTExponent().toString());

		assertEquals("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
			"AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
			"bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
			"T1cYF8", jwk.getSecondFactorCRTExponent().toString());

		assertEquals("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
			"ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
			"jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
			"z8aaI4", jwk.getFirstCRTCoefficient().toString());

		// Convert to Java RSA key object
		RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
		RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

		jwk = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

		assertEquals("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ", jwk.getPrivateExponent().toString());
	}
}
