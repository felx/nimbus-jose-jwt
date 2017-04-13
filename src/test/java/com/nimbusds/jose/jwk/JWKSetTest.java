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
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static net.jadler.Jadler.*;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
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
 * Tests JSON Web Key (JWK) set parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-04-13
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
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());

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
		
		ECParameterSpec ecParameterSpec = ECKey.Curve.P_256.toECParameterSpec();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();
		
		ECKey ecKey = new ECKey.Builder(ECKey.Curve.P_256, (ECPublicKey)keyPair.getPublic())
			.privateKey((ECPrivateKey) keyPair.getPrivate())
			.keyUse(KeyUse.ENCRYPTION)
			.algorithm(JWEAlgorithm.ECDH_ES)
			.keyID("1234")
			.build();

		RSAKey rsaKey = new RSAKey.Builder(new Base64URL("abc"), new Base64URL("def"))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("5678")
			.build();

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
		ECKey ecKeyOut = (ECKey)keySet.getKeys().get(0);
		assertNotNull(ecKeyOut);
		assertEquals(ECKey.Curve.P_256, ecKeyOut.getCurve());
		assertEquals(ecKey.getX(), ecKeyOut.getX());
		assertEquals(ecKey.getY(), ecKeyOut.getY());
		assertEquals(KeyUse.ENCRYPTION, ecKeyOut.getKeyUse());
		assertNull(ecKeyOut.getKeyOperations());
		assertEquals(JWEAlgorithm.ECDH_ES, ecKeyOut.getAlgorithm());
		assertEquals("1234", ecKeyOut.getKeyID());

		// Check second RSA key
		RSAKey rsaKeyOut = (RSAKey)keySet.getKeys().get(1);
		assertNotNull(rsaKeyOut);
		assertEquals("abc", rsaKeyOut.getModulus().toString());
		assertEquals("def", rsaKeyOut.getPublicExponent().toString());
		assertEquals(KeyUse.SIGNATURE, rsaKeyOut.getKeyUse());
		assertNull(rsaKeyOut.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, rsaKeyOut.getAlgorithm());
		assertEquals("5678", rsaKeyOut.getKeyID());

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
		assertNull(key.getKeyOperations());
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
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());
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
		assertNull(key.getKeyOperations());
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
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());
		assertNull(key.getKeyOperations());

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
		assertNull(key.getKeyOperations());
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
	
	public void testGetByKeyId() throws Exception{
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

		
		// Check first EC key
		JWK key = keySet.getKeyByKeyId("1");

		assertTrue(key instanceof ECKey);
		assertEquals("1", key.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());

		ECKey ecKey = (ECKey)key;
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
		assertFalse(key.isPrivate());


		// Check second RSA key
		key = keySet.getKeyByKeyId("2011-04-29");
		assertTrue(key instanceof RSAKey);
		assertEquals("2011-04-29", key.getKeyID());
		assertNull(key.getKeyUse());
		assertNull(key.getKeyOperations());
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


	public void testOctJWKSetPublicExport()
		throws Exception {

		OctetSequenceKey oct1 = new OctetSequenceKey.Builder(new Base64URL("abc")).build();
		assertEquals("abc", oct1.getKeyValue().toString());

		OctetSequenceKey oct2 = new OctetSequenceKey.Builder(new Base64URL("def")).build();
		assertEquals("def", oct2.getKeyValue().toString());

		List<JWK> keyList = new LinkedList<>();
		keyList.add(oct1);
		keyList.add(oct2);

		JWKSet privateSet = new JWKSet(keyList);

		final boolean publicParamsOnly = true;
		JSONObject jsonObject = privateSet.toJSONObject(publicParamsOnly);

		JWKSet publicSet = JWKSet.parse(jsonObject.toJSONString());

		assertEquals(0, publicSet.getKeys().size());
	}


	public void testOctJWKSetToPublic()
		throws Exception {

		OctetSequenceKey oct1 = new OctetSequenceKey.Builder(new Base64URL("abc")).build();
		assertEquals("abc", oct1.getKeyValue().toString());

		OctetSequenceKey oct2 = new OctetSequenceKey.Builder(new Base64URL("def")).build();
		assertEquals("def", oct2.getKeyValue().toString());

		List<JWK> keyList = new LinkedList<>();
		keyList.add(oct1);
		keyList.add(oct2);

		JWKSet privateSet = new JWKSet(keyList);

		JWKSet publicSet = privateSet.toPublicJWKSet();

		assertEquals(0, publicSet.getKeys().size());
	}


	public void testMIMEType() {

		assertEquals("application/jwk-set+json; charset=UTF-8", JWKSet.MIME_TYPE);
	}


	public void testLoadFromFile()
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

		File file = new File("TEST.jwkset.json");
		PrintWriter printWriter = new PrintWriter(file);
		printWriter.print(s);
		printWriter.close();

		JWKSet keySet = JWKSet.load(file);


		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());


		// Check first EC key
		JWK key = keyList.get(0);

		assertTrue(key instanceof ECKey);
		assertEquals("1", key.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());

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

		Files.delete(file.toPath());
	}
	
	
	public void testLoadFromNonExistingFile()
		throws ParseException {
		
		try {
			JWKSet.load(new File("no-such-file"));
			fail();
		} catch (IOException e) {
			assertEquals("no-such-file (No such file or directory)", e.getMessage());
		}
	}


	public void testLoadFromURL()
		throws Exception {

		initJadler();

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

		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withBody(s)
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("application/json");

		JWKSet keySet = JWKSet.load(new URL("http://localhost:" + port()));


		List<JWK> keyList = keySet.getKeys();
		assertEquals(2, keyList.size());


		// Check first EC key
		JWK key = keyList.get(0);

		assertTrue(key instanceof ECKey);
		assertEquals("1", key.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, key.getKeyUse());

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

		closeJadler();
	}
	
	
	public void testLoadFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// AES key
		KeyGenerator secGen = KeyGenerator.getInstance("AES");
		secGen.init(128);
		SecretKey secretKey = secGen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		// RSA key pair
		KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
		rsaGen.initialize(1024);
		KeyPair kp = rsaGen.generateKeyPair();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)kp.getPrivate();
		
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
			rsaPublicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(rsaPrivateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		keyStore.setKeyEntry("2", rsaPrivateKey, "".toCharArray(), new Certificate[]{cert});
		
		
		// EC key pair
		KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
		ecGen.initialize(ECKey.Curve.P_521.toECParameterSpec());
		KeyPair ecKP = ecGen.generateKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey)ecKP.getPublic();
		ECPrivateKey ecPrivateKey = (ECPrivateKey)ecKP.getPrivate();
		
		// Generate certificate
		issuer = new X500Name("cn=c2id");
		serialNumber = new BigInteger(64, new SecureRandom());
		now = new Date();
		nbf = new Date(now.getTime() - 1000L);
		exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		subject = new X500Name("cn=c2id");
		x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			ecPublicKey
		);
		keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		certHolder = x509certBuilder.build(signerBuilder.build(ecPrivateKey));
		cert = X509CertUtils.parse(certHolder.getEncoded());
		keyStore.setKeyEntry("3", ecPrivateKey, "".toCharArray(), new java.security.cert.Certificate[]{cert});
		
		
		
		// Load
		JWKSet jwkSet = JWKSet.load(keyStore, new PasswordLookup() {
			@Override
			public char[] lookupPassword(final String name) {
				if ("1".equalsIgnoreCase(name)) return "1234".toCharArray();
				else return "".toCharArray();
			}
		});
		
		
		OctetSequenceKey octJWK = (OctetSequenceKey) jwkSet.getKeyByKeyId("1");
		assertNotNull(octJWK);
		assertEquals("1", octJWK.getKeyID());
		assertTrue(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray()));
		assertEquals(keyStore, octJWK.getKeyStore());
		
		RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId("2");
		assertNotNull(rsaKey);
		assertEquals(KeyUse.SIGNATURE, rsaKey.getKeyUse());
		assertEquals("2", rsaKey.getKeyID());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertNotNull(rsaKey.getX509CertSHA256Thumbprint());
		assertTrue(rsaKey.isPrivate());
		assertEquals(keyStore, rsaKey.getKeyStore());
		
		ECKey ecKey = (ECKey) jwkSet.getKeyByKeyId("3");
		assertNotNull(ecKey);
		assertEquals(ECKey.Curve.P_521, ecKey.getCurve());
		assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
		assertEquals("3", ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertNotNull(ecKey.getX509CertSHA256Thumbprint());
		assertTrue(ecKey.isPrivate());
		assertEquals(keyStore, ecKey.getKeyStore());
		
		assertEquals(3, jwkSet.getKeys().size());
	}
}
