package com.nimbusds.jwt.proc;


import java.net.URL;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import junit.framework.TestCase;


/**
 * Tests the default JWT processor.
 *
 * @version 2016-04-11
 */
public class DefaultJWTProcessorTest extends TestCase {


	public void testConstructor()
		throws Exception {

		ConfigurableJWTProcessor processor = new DefaultJWTProcessor();

		assertNull(processor.getJWSKeySelector());
		assertNull(processor.getJWEKeySelector());

		assertTrue(processor.getJWSVerifierFactory() instanceof DefaultJWSVerifierFactory);
		assertTrue(processor.getJWEDecrypterFactory() instanceof DefaultJWEDecrypterFactory);

		assertTrue(processor.getJWTClaimsVerifier() instanceof DefaultJWTClaimsVerifier);
	}


	public void testVerifyClaimsAllow()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		processor.setJWTClaimsVerifier(new JWTClaimsVerifier() {
			@Override
			public void verify(JWTClaimsSet claimsSet) throws BadJWTException {
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});

		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());
		assertEquals("https://openid.c2id.com", processor.process(jwt.serialize(), null).getIssuer());
	}


	public void testVerifyClaimsDeny()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://test.c2id.com")
			.subject("alice")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		processor.setJWTClaimsVerifier(new JWTClaimsVerifier() {
			@Override
			public void verify(JWTClaimsSet claimsSet) throws BadJWTException {
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});

		try {
			processor.process(jwt.serialize(), null);
			fail();
		} catch (BadJWTException e) {

			assertEquals("Unexpected/missing issuer", e.getMessage());
		}
	}


	public void testProcessHmacJWTWithTwoKeyCandidates()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				// first key candidate invalid, the second is correct
				return Arrays.asList(new SecretKeySpec(new byte[32], "HMAC"), key);
			}
		});

		assertEquals("alice", processor.process(jwt, null).getSubject());
		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());
	}


	public void testProcessEncryptedJWTWithTwoKeyCandidates()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
		EncryptedJWT jwt = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), claims);

		byte[] keyBytes = new byte[16];
		new SecureRandom().nextBytes(keyBytes);

		final SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());

		jwt.encrypt(new DirectEncrypter(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				// First key invalid, second valid
				return Arrays.asList(new SecretKeySpec(new byte[16], "AES"), key);
			}
		});

		assertEquals("alice", processor.process(jwt, null).getSubject());
		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());

		Security.removeProvider(BouncyCastleProviderSingleton.getInstance().getName());
	}


	public void testProcessNestedJWT()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7519#appendix-A.2

		String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> joseProcessor = new DefaultJWTProcessor<>();
		joseProcessor.setJWTClaimsVerifier(null); // Remove claims verifier, JWT past expiration timestamp

		joseProcessor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {

				if (header.getAlgorithm().equals(JWSAlgorithm.RS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
						"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
						"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
						"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
						"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
						"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
						"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
						"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
						"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
						"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
						"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
						"\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
						"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
						"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
						"\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
						"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
						"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
						"\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
						"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
						"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
						"\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
						"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
						"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
						"\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
						"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
						"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
						"}";

					try {
						Key rsaPublicKey = RSAKey.parse(jwk).toRSAPublicKey();
						return Collections.singletonList(rsaPublicKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}
				return null;
			}
		});

		joseProcessor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {

				// {"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}
				if (header.getAlgorithm().equals(JWEAlgorithm.RSA1_5) && header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
						"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
						"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
						"7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
						"Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
						"7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
						"1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
						"nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
						"0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
						"-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
						"T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
						"\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
						"ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
						"krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
						"\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
						"BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
						"-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
						"\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
						"ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
						"Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
						"\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
						"7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
						"odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
						"\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
						"tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
						"B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
						"}";

					try {
						Key rsaPrivateKey = RSAKey.parse(jwk).toRSAPrivateKey();
						return Collections.singletonList(rsaPrivateKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}

				return null;
			}
		});


		assertNotNull(joseProcessor.getJWSKeySelector());
		assertNotNull(joseProcessor.getJWEKeySelector());

		JWTClaimsSet claims = joseProcessor.process(jwt, new SimpleSecurityContext());

		assertEquals("joe", claims.getIssuer());
		assertEquals(1300819380L * 1000L, claims.getExpirationTime().getTime());
		assertTrue(claims.getBooleanClaim("http://example.com/is_root"));
		assertEquals(3, claims.getClaims().size());
	}


	public void testRejectPlain()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

		PlainJWT jwt = new PlainJWT(claims);

		try {
			new DefaultJWTProcessor<>().process(jwt, null);
		} catch (BadJOSEException e) {
			assertEquals("Unsecured (plain) JWTs are rejected, extend class to handle", e.getMessage());
		}

		try {
			new DefaultJWTProcessor<>().process(jwt.serialize(), null);
		} catch (BadJOSEException e) {
			assertEquals("Unsecured (plain) JWTs are rejected, extend class to handle", e.getMessage());
		}
	}


	public void testNoJWSKeyCandidates()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7515#appendix-A.1
		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return new LinkedList<>(); // empty
			}
		});

		try {
			processor.process(jws, null);
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No matching key(s) found", e.getMessage());
		}
	}


	public void testNoJWEKeyCandidates()
		throws Exception {

		String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				return new LinkedList<>(); // no candidates
			}
		});

		try {
			processor.process(jwt, null);
		} catch (BadJOSEException e) {
			assertEquals("Encrypted JWT rejected: No matching key(s) found", e.getMessage());
		}
	}


	public void testNoJWSKeySelector()
		throws Exception {

		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		try {
			processor.process(jws, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No JWS key selector is configured", e.getMessage());
		}
	}


	public void testNoJWSFactory()
		throws Exception {

		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				Key key = new SecretKeySpec(new Base64URL("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow").decode(), "HMAC");
				return Collections.singletonList(key);
			}
		});

		processor.setJWSVerifierFactory(null);

		try {
			processor.process(jws, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("No JWS verifier is configured", e.getMessage());
		}
	}


	public void testNoJWEKeySelector()
		throws Exception {

		String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		try {
			processor.process(jwe, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Encrypted JWT rejected: No JWE key selector is configured", e.getMessage());
		}
	}


	public void testNoJWEFactory()
		throws Exception {

		String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				// {"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}
				if (header.getAlgorithm().equals(JWEAlgorithm.RSA1_5) && header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
						"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
						"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
						"7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
						"Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
						"7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
						"1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
						"nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
						"0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
						"-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
						"T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
						"\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
						"ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
						"krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
						"\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
						"BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
						"-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
						"\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
						"ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
						"Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
						"\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
						"7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
						"odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
						"\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
						"tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
						"B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
						"}";

					try {
						Key rsaPrivateKey = RSAKey.parse(jwk).toRSAPrivateKey();
						return Collections.singletonList(rsaPrivateKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}

				return null;
			}
		});

		processor.setJWEDecrypterFactory(null);

		try {
			processor.process(jwe, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("No JWE decrypter is configured", e.getMessage());
		}
	}


	public void testJWTExpired()
		throws Exception {

		final Date now = new Date();
		final Date yesterday = new Date(now.getTime() - 24*60*60*1000);

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.expirationTime(yesterday)
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		try {
			processor.process(jwt.serialize(), null);
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testJWTBeforeUse()
		throws Exception {

		final Date now = new Date();
		final Date tomorrow = new Date(now.getTime() + 24*60*60*1000);

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.notBeforeTime(tomorrow)
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		try {
			processor.process(jwt.serialize(), null);
		} catch (BadJWTException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}


	// Example for the WiKi
	public void _testValidateJWTAccessToken()
		throws Exception {

		// The access token to validate, typically submitted with a HTTP header like
		// Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3A...
		String accessToken =
			"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxl" +
			"Il0sImV4cCI6MTQ2MDM0NTczNiwic3ViIjoiYWxpY2UiLCJpc3MiOiJodHRwczpcL1wvZGVtby5jMmlk" +
			"LmNvbVwvYzJpZCIsInVpcCI6eyJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfSwiY2xtIjpbIiE1djhI" +
			"Il0sImNpZCI6IjAwMDEyMyJ9.Xeg3cMrePht8R0731mfndUDoX48NWhfCuEjcEERcZ3krfnOacNJzyJd" +
			"7zOWdNrlvEpJMjmmgkbhZOMJlVMv4fQnGB2d3eevmtjuT7hMnJVQc_4h80ODHPMlW27T0Iukpe7Y-A-R" +
			"rROP5yinry7BFBL2nVWrNtB9IS11H9C8X5fQ";

		// Set up a JWT processor to parse the tokens and then check their signature
		// and validity time window (bounded by the "iat", "nbf" and "exp" claims)
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also gracefully handle key-rollover
		JWKSource keySource = new RemoteJWKSet(new URL("https://demo.c2id.com/c2id/jwks.json"));

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
	}


	// Wiki example
	public void testWithEncryption()
		throws Exception {

		byte[] secret = new byte[32];

		// The AES key, obtained from a Java keystore, etc.
		SecretKey secretKey = new SecretKeySpec(secret, "AES");

		// The expected JWE algorithm and method
		JWEAlgorithm expectedJWEAlg = JWEAlgorithm.DIR;
		EncryptionMethod expectedJWEEnc = EncryptionMethod.A128GCM;

		// The JWE key source
		JWKSource jweKeySource = new ImmutableSecret(secretKey);

		// Configure a key selector to handle the decryption phase
		JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, jweKeySource);

		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWEKeySelector(jweKeySelector);

		jwtProcessor.setJWTClaimsVerifier(new DefaultJWTClaimsVerifier() {

			@Override
			public void verify(JWTClaimsSet claimsSet)
				throws BadJWTException {

				super.verify(claimsSet);

				String issuer = claimsSet.getIssuer();

				if (issuer == null || ! issuer.equals("https://demo.c2id.com/c2id")) {
					throw new BadJWTException("Invalid token issuer");
				}
			}
		});
	}
}
