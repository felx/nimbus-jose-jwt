package com.nimbusds.jose.jwk;


import java.text.ParseException;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JSON Web Key (JWK) set parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-21)
 */
public class JWKSetTest extends TestCase {


	public void testParsePublicJWKSet()
		throws Exception {

		// The string is from the JWK spec
		String s = "{\"keys\":" +
			   "[" +
			   "{\"kty\":\"EC\"," +
			   "\"crv\":\"P-256\"," +
			   "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
			   "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
			   "\"use\":\"enc\"," +
			   "\"kid\":\"1\"}," +
			   " " +
			   "{\"kty\":\"RSA\"," +
			   "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			   "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			   "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			   "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			   "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			   "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
			   "\"e\":\"AQAB\"," +
			   "\"alg\":\"RS256\"," +
			   "\"kid\":\"2011-04-29\"}" +
			   "]" +
			   "}";

		
		JWKSet keySet = JWKSet.parse(s);


		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());


		// Check first EC key
		JWK key = keyList.get(0);

		assertTrue(key instanceof ECKey);
		assertEquals("1", key.getKeyID());
		assertEquals(Use.ENCRYPTION, key.getKeyUse());

		ECKey ecKey = (ECKey)key;
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
		assertFalse(key.isPrivate());


		// Check second RSA key
		key = keyList.get(1);
		assertTrue(key instanceof RSAKey);
		assertEquals("2011-04-29", key.getKeyID());
		assertNull(key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());

		RSAKey rsaKey = (RSAKey)key;
		assertEquals("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		             "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
		             "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
		             "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
		             "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
		             "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 
		             rsaKey.getModulus().toString());
		assertEquals("AQAB", rsaKey.getPublicExponent().toString());
		assertFalse(key.isPrivate());
	}


	public void testSerializeAndParsePublicJWKSet()
		throws Exception {

		ECKey ecKey = new ECKey(ECKey.Curve.P_256, 
				new Base64URL("abc"), 
				new Base64URL("def"),
				Use.ENCRYPTION,
				JWEAlgorithm.ECDH_ES,
				"1234");

		RSAKey rsaKey = new RSAKey(new Base64URL("abc"),
				new Base64URL("def"),
				Use.SIGNATURE,
				JWSAlgorithm.RS256,
				"5678");

		JWKSet keySet = new JWKSet();

		keySet.getKeys().add(ecKey);
		keySet.getKeys().add(rsaKey);

		assertEquals(0, keySet.getAdditionalMembers().size());

		keySet.getAdditionalMembers().put("setID", "xyz123");

		assertEquals(1, keySet.getAdditionalMembers().size());

		String s = keySet.toString();
		
		keySet = JWKSet.parse(s);

		assertNotNull(keySet);
		assertEquals(2, keySet.getKeys().size());

		// Check first EC key
		ecKey = (ECKey)keySet.getKeys().get(0);
		assertNotNull(ecKey);
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("abc", ecKey.getX().toString());
		assertEquals("def", ecKey.getY().toString());
		assertEquals(Use.ENCRYPTION, ecKey.getKeyUse());
		assertEquals(JWEAlgorithm.ECDH_ES, ecKey.getAlgorithm());
		assertEquals("1234", ecKey.getKeyID());

		// Check second RSA key
		rsaKey = (RSAKey)keySet.getKeys().get(1);
		assertNotNull(rsaKey);
		assertEquals("abc", rsaKey.getModulus().toString());
		assertEquals("def", rsaKey.getPublicExponent().toString());
		assertEquals(Use.SIGNATURE, rsaKey.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, rsaKey.getAlgorithm());
		assertEquals("5678", rsaKey.getKeyID());

		// Check additional JWKSet members
		assertEquals(1, keySet.getAdditionalMembers().size());
		assertEquals("xyz123", (String)keySet.getAdditionalMembers().get("setID"));
	}


	public void testParseOctetSequenceJWKSet()
		throws Exception {

		// The string is from the JPSK spec
		String s = "{\"keys\":" +
		           "[" +
		           " {\"kty\":\"oct\"," +
		           "  \"alg\":\"A128KW\", " +
		           "  \"k\":\"GawgguFyGrWKav7AX4VKUg\"}," +
		           " {\"kty\":\"oct\", "+
		           "  \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"," +
		           "  \"kid\":\"HMAC key used in JWS A.1 example\"} " +
		           "]" +
		           "}";


		JWKSet keySet = JWKSet.parse(s);


		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());

		// First OCT key
		JWK key = keyList.get(0);
		assertTrue(key instanceof OctetSequenceKey);
		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertEquals(JWEAlgorithm.A128KW, key.getAlgorithm());
		assertNull(key.getKeyID());
		assertEquals(new Base64URL("GawgguFyGrWKav7AX4VKUg"), ((OctetSequenceKey)key).getKeyValue());

		// Second OCT key
		key = keyList.get(1);
		assertTrue(key instanceof OctetSequenceKey);
		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertNull(key.getAlgorithm());
		assertEquals("HMAC key used in JWS A.1 example", key.getKeyID());
		assertEquals(new Base64URL("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), ((OctetSequenceKey)key).getKeyValue());
	}


	public void testParsePrivateJWKSet()
		throws Exception {

		// The string is from the JPSK spec
		String s = "{\"keys\":" +
		           "  [" +
		           "    {\"kty\":\"EC\"," +
		           "     \"crv\":\"P-256\"," +
		           "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
		           "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
		           "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
		           "     \"use\":\"enc\"," +
		           "     \"kid\":\"1\"}," +
		           "" +
		           "    {\"kty\":\"RSA\"," +
		           "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
		           "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
		           "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
		           "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
		           "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
		           "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
		           "     \"e\":\"AQAB\"," +
		           "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
		           "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
		           "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
		           "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
		           "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
		           "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
		           "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
		           "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
		           "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
		           "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
		           "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
		           "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
		           "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
		           "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
		           "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
		           "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
		           "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
		           "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
		           "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
		           "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
		           "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
		           "     \"alg\":\"RS256\"," +
		           "     \"kid\":\"2011-04-29\"}" +
		           "  ]" +
		           "}";

		JWKSet keySet = null;

		try {
			keySet = JWKSet.parse(s);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());


		// Check EC key
		JWK key = keyList.get(0);
		assertTrue(key instanceof ECKey);
		assertEquals(Use.ENCRYPTION, key.getKeyUse());
		assertNull(key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		ECKey ecKey = (ECKey)key;

		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
		assertEquals("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", ecKey.getD().toString());

		assertNull(ecKey.toPublicJWK().getD());


		// Check RSA key
		key = keyList.get(1);
		assertTrue(key instanceof RSAKey);
		assertNull(key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("2011-04-29", key.getKeyID());

		RSAKey rsaKey = (RSAKey)key;

		assertEquals("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		             "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
		             "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
		             "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
		             "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
		             "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 
		             rsaKey.getModulus().toString());

		assertEquals("AQAB", rsaKey.getPublicExponent().toString());


		assertEquals("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
		             "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
		             "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
		             "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
		             "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
		             "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
		             rsaKey.getPrivateExponent().toString());

		assertEquals("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
		             "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
		             "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
		             rsaKey.getFirstPrimeFactor().toString());

		assertEquals("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
		             "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
		             "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
		             rsaKey.getSecondPrimeFactor().toString());

		assertEquals("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
		             "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
		             "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
		             rsaKey.getFirstFactorCRTExponent().toString());

		assertEquals("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
		             "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
		             "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
		             rsaKey.getSecondFactorCRTExponent().toString());

		assertEquals("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
		             "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
		             "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
		             rsaKey.getFirstCRTCoefficient().toString());

		assertTrue(rsaKey.getOtherPrimes().isEmpty());

		assertNull(rsaKey.toPublicJWK().getPrivateExponent());
		assertNull(rsaKey.toPublicJWK().getFirstPrimeFactor());
		assertNull(rsaKey.toPublicJWK().getSecondPrimeFactor());
		assertNull(rsaKey.toPublicJWK().getFirstFactorCRTExponent());
		assertNull(rsaKey.toPublicJWK().getSecondFactorCRTExponent());
		assertNull(rsaKey.toPublicJWK().getFirstCRTCoefficient());
		assertTrue(rsaKey.toPublicJWK().getOtherPrimes().isEmpty());
	}


	public void testPublicJSONObjectSerialization()
		throws Exception {

		// The string is from the JPSK spec
		String s = "{\"keys\":" +
		           "  [" +
		           "    {\"kty\":\"EC\"," +
		           "     \"crv\":\"P-256\"," +
		           "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
		           "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
		           "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
		           "     \"use\":\"enc\"," +
		           "     \"kid\":\"1\"}," +
		           "" +
		           "    {\"kty\":\"RSA\"," +
		           "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
		           "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
		           "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
		           "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
		           "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
		           "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
		           "     \"e\":\"AQAB\"," +
		           "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
		           "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
		           "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
		           "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
		           "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
		           "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
		           "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
		           "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
		           "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
		           "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
		           "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
		           "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
		           "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
		           "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
		           "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
		           "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
		           "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
		           "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
		           "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
		           "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
		           "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
		           "     \"alg\":\"RS256\"," +
		           "     \"kid\":\"2011-04-29\"}" +
		           "  ]" +
		           "}";


		JWKSet keySet = JWKSet.parse(s);


		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());

		final boolean publicParamsOnly = true;


		// Strip all private parameters
		s = keySet.toJSONObject(publicParamsOnly).toString();

		keySet = JWKSet.parse(s);

		keyList = keySet.getKeys();
		assertEquals(2, keyList.size());

		// Check first EC key
		JWK key = keyList.get(0);

		assertTrue(key instanceof ECKey);
		assertEquals("1", key.getKeyID());
		assertEquals(Use.ENCRYPTION, key.getKeyUse());

		ECKey ecKey = (ECKey)key;
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
		assertFalse(key.isPrivate());


		// Check second RSA key
		key = keyList.get(1);
		assertTrue(key instanceof RSAKey);
		assertEquals("2011-04-29", key.getKeyID());
		assertNull(key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());

		RSAKey rsaKey = (RSAKey)key;
		assertEquals("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
		             "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
		             "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
		             "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
		             "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
		             "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 
		             rsaKey.getModulus().toString());
		assertEquals("AQAB", rsaKey.getPublicExponent().toString());
		assertFalse(key.isPrivate());
	}
}
