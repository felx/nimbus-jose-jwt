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

package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import junit.framework.TestCase;


/**
 * Tests RSAES OAEP JWE encryption and decryption. Uses test RSA keys from the 
 * JWE spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-04
 */
public class RSA_OAEPTest extends TestCase {


	private final static byte[] MOD = {
		(byte)161, (byte)168, (byte) 84, (byte) 34, (byte)133, (byte)176, (byte)208, (byte)173, 
		(byte) 46, (byte)176, (byte)163, (byte)110, (byte) 57, (byte) 30, (byte)135, (byte)227, 
		(byte)  9, (byte) 31, (byte)226, (byte)128, (byte) 84, (byte) 92, (byte)116, (byte)241, 
		(byte) 70, (byte)248, (byte) 27, (byte)227, (byte)193, (byte) 62, (byte)  5, (byte) 91, 
		(byte)241, (byte)145, (byte)224, (byte)205, (byte)141, (byte)176, (byte)184, (byte)133, 

		(byte)239, (byte) 43, (byte) 81, (byte)103, (byte)  9, (byte)161, (byte)153, (byte)157, 
		(byte)179, (byte)104, (byte)123, (byte) 51, (byte)189, (byte) 34, (byte)152, (byte) 69, 
		(byte) 97, (byte) 69, (byte) 78, (byte) 93, (byte)140, (byte)131, (byte) 87, (byte)182, 
		(byte)169, (byte)101, (byte) 92, (byte)142, (byte)  3, (byte) 22, (byte)167, (byte)  8, 
		(byte)212, (byte) 56, (byte) 35, (byte) 79, (byte)210, (byte)222, (byte)192, (byte)208, 

		(byte)252, (byte) 49, (byte)109, (byte)138, (byte)173, (byte)253, (byte)210, (byte)166, 
		(byte)201, (byte) 63, (byte)102, (byte) 74, (byte)  5, (byte)158, (byte) 41, (byte) 90, 
		(byte)144, (byte)108, (byte)160, (byte) 79, (byte) 10, (byte) 89, (byte)222, (byte)231,  
		(byte)172, (byte) 31, (byte)227, (byte)197, (byte)  0, (byte) 19, (byte) 72, (byte) 81, 
		(byte)138, (byte) 78, (byte)136, (byte)221, (byte)121, (byte)118, (byte)196, (byte) 17,

		(byte)146, (byte) 10, (byte)244, (byte)188, (byte) 72, (byte)113, (byte) 55, (byte)221, 
		(byte)162, (byte)217, (byte)171, (byte) 27, (byte) 57, (byte)233, (byte)210, (byte)101, 
		(byte)236, (byte)154, (byte)199, (byte) 56, (byte)138, (byte)239, (byte)101, (byte) 48, 
		(byte)198, (byte)186, (byte)202, (byte)160, (byte) 76, (byte)111, (byte)234, (byte) 71, 
		(byte) 57, (byte)183, (byte)  5, (byte)211, (byte)171, (byte)136, (byte)126, (byte) 64, 

		(byte) 40, (byte) 75, (byte) 58, (byte) 89, (byte)244, (byte)254, (byte)107, (byte) 84, 
		(byte)103, (byte)  7, (byte)236, (byte) 69, (byte)163, (byte) 18, (byte)180, (byte)251, 
		(byte) 58, (byte)153, (byte) 46, (byte)151, (byte)174, (byte) 12, (byte)103, (byte)197, 
		(byte)181, (byte)161, (byte)162, (byte) 55, (byte)250, (byte)235, (byte)123, (byte)110, 
		(byte) 17, (byte) 11, (byte)158, (byte) 24, (byte) 47, (byte)133, (byte)  8, (byte)199, 

		(byte)235, (byte)107, (byte)126, (byte)130, (byte)246, (byte) 73, (byte)195, (byte) 20, 
		(byte)108, (byte)202, (byte)176, (byte)214, (byte)187, (byte) 45, (byte)146, (byte)182, 
		(byte)118, (byte) 54, (byte) 32, (byte)200, (byte) 61, (byte)201, (byte) 71, (byte)243, 
		(byte)  1, (byte)255, (byte)131, (byte) 84, (byte) 37, (byte)111, (byte)211, (byte)168, 
		(byte)228, (byte) 45, (byte)192, (byte)118, (byte) 27, (byte)197, (byte)235, (byte)232,  

		(byte) 36, (byte) 10, (byte)230, (byte)248, (byte)190, (byte) 82, (byte)182, (byte)140, 
		(byte) 35, (byte)204, (byte)108, (byte)190, (byte)253, (byte)186, (byte)186, (byte)27  };


	private static final byte[] EXP = { 1, 0, 1 };


	private static final byte[] MOD_PRIV = {
		(byte)144, (byte)183, (byte)109, (byte) 34, (byte) 62, (byte)134, (byte)108, (byte) 57, 
		(byte) 44, (byte)252, (byte) 10, (byte) 66, (byte) 73, (byte) 54, (byte) 16, (byte)181, 
		(byte)233, (byte) 92, (byte) 54, (byte)219, (byte)101, (byte) 42, (byte) 35, (byte)178, 
		(byte) 63, (byte) 51, (byte) 43, (byte) 92, (byte)119, (byte)136, (byte)251, (byte) 41, 
		(byte) 53, (byte) 23, (byte)191, (byte)164, (byte)164, (byte) 60, (byte) 88, (byte)227, 

		(byte)229, (byte)152, (byte)228, (byte)213, (byte)149, (byte)228, (byte)169, (byte)237, 
		(byte)104, (byte) 71, (byte)151, (byte) 75, (byte) 88, (byte)252, (byte)216, (byte) 77, 
		(byte)251, (byte)231, (byte) 28, (byte) 97, (byte) 88, (byte)193, (byte)215, (byte)202, 
		(byte)248, (byte)216, (byte)121, (byte)195, (byte)211, (byte)245, (byte)250, (byte)112, 
		(byte) 71, (byte)243, (byte) 61, (byte)129, (byte) 95, (byte) 39, (byte)244, (byte)122, 

		(byte)225, (byte)217, (byte)169, (byte)211, (byte)165, (byte) 48, (byte)253, (byte)220, 
		(byte) 59, (byte)122, (byte)219, (byte) 42, (byte) 86, (byte)223, (byte) 32, (byte)236, 
		(byte) 39, (byte) 48, (byte)103, (byte) 78, (byte)122, (byte)216, (byte)187, (byte) 88, 
		(byte)176, (byte) 89, (byte) 24, (byte)  1, (byte) 42, (byte)177, (byte) 24, (byte) 99, 
		(byte)142, (byte)170, (byte)  1, (byte)146, (byte) 43, (byte)  3, (byte)108, (byte) 64, 

		(byte)194, (byte)121, (byte)182, (byte) 95, (byte)187, (byte)134, (byte) 71, (byte) 88, 
		(byte) 96, (byte)134, (byte) 74, (byte)131, (byte)167, (byte) 69, (byte)106, (byte)143, 
		(byte)121, (byte) 27, (byte) 72, (byte) 44, (byte)245, (byte) 95, (byte) 39, (byte)194, 
		(byte)179, (byte)175, (byte)203, (byte)122, (byte) 16, (byte)112, (byte)183, (byte) 17, 
		(byte)200, (byte)202, (byte) 31, (byte) 17, (byte)138, (byte)156, (byte)184, (byte)210, 

		(byte)157, (byte)184, (byte)154, (byte)131, (byte)128, (byte)110, (byte) 12, (byte) 85, 
		(byte)195, (byte)122, (byte)241, (byte) 79, (byte)251, (byte)229, (byte)183, (byte)117, 
		(byte) 21, (byte)123, (byte)133, (byte)142, (byte)220, (byte)153, (byte)  9, (byte) 59, 
		(byte) 57, (byte)105, (byte) 81, (byte)255, (byte)138, (byte) 77, (byte) 82, (byte) 54, 
		(byte) 62, (byte)216, (byte) 38, (byte)249, (byte)208, (byte) 17, (byte)197, (byte) 49, 

		(byte) 45, (byte) 19, (byte)232, (byte)157, (byte)251, (byte)131, (byte)137, (byte)175, 
		(byte) 72, (byte)126, (byte) 43, (byte)229, (byte) 69, (byte)179, (byte)117, (byte) 82,  
		(byte)157, (byte)213, (byte) 83, (byte) 35, (byte) 57, (byte)210, (byte)197, (byte)252, 
		(byte)171, (byte)143, (byte)194, (byte) 11, (byte) 47, (byte)163, (byte)  6, (byte)253, 
		(byte) 75, (byte)252, (byte) 96, (byte) 11, (byte)187, (byte) 84, (byte)130, (byte)210, 

		(byte)  7, (byte)121, (byte) 78, (byte) 91, (byte) 79, (byte) 57, (byte)251, (byte)138, 
		(byte)132, (byte)220, (byte) 60, (byte)224, (byte)173, (byte) 56, (byte)224, (byte)201  };


	private static RSAPublicKey PUBLIC_KEY;


	private static PrivateKey PRIVATE_KEY;


	static {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, MOD), new BigInteger(1, EXP));
			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, MOD), new BigInteger(1, MOD_PRIV));

			PUBLIC_KEY = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			PRIVATE_KEY = keyFactory.generatePrivate(privateKeySpec);

		} catch (Exception e) {

			fail(e.getMessage());
		}
	}
	
	
	public void testRoundTripWithAllWithEncs()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		List<EncryptionMethod> encs = Arrays.asList(
			EncryptionMethod.A128CBC_HS256,
			EncryptionMethod.A192CBC_HS384,
			EncryptionMethod.A256CBC_HS512,
			EncryptionMethod.A128GCM,
			EncryptionMethod.A192GCM,
			EncryptionMethod.A256GCM,
			EncryptionMethod.A128CBC_HS256_DEPRECATED,
			EncryptionMethod.A256CBC_HS512_DEPRECATED);
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		
		for (EncryptionMethod enc: encs) {
			
			JWEObject jwe = new JWEObject(
				new JWEHeader(JWEAlgorithm.RSA_OAEP, enc),
				new Payload("Hello, world!"));
			
			assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
			
			jwe.encrypt(encrypter);
			
			assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
			
			String jweString = jwe.serialize();
			
			jwe = JWEObject.parse(jweString);
			
			jwe.decrypt(decrypter);
			
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			
			assertEquals("Hello, world!", jwe.getPayload().toString());
		}
	}
	
	
	public void testRoundTripWithAllWithEncs_withBouncyCastleProvider()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		List<EncryptionMethod> encs = Arrays.asList(
			EncryptionMethod.A128CBC_HS256,
			EncryptionMethod.A192CBC_HS384,
			EncryptionMethod.A256CBC_HS512,
			EncryptionMethod.A128GCM,
			EncryptionMethod.A192GCM,
			EncryptionMethod.A256GCM,
			EncryptionMethod.A128CBC_HS256_DEPRECATED,
			EncryptionMethod.A256CBC_HS512_DEPRECATED);
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		for (EncryptionMethod enc: encs) {
			
			JWEObject jwe = new JWEObject(
				new JWEHeader(JWEAlgorithm.RSA_OAEP_256, enc),
				new Payload("Hello, world!"));
			
			assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
			
			jwe.encrypt(encrypter);
			
			assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
			
			String jweString = jwe.serialize();
			
			jwe = JWEObject.parse(jweString);
			
			jwe.decrypt(decrypter);
			
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			
			assertEquals("Hello, world!", jwe.getPayload().toString());
		}
	}
	
	
	public void testRFCExampleDecryptWith256GCM()
		throws Exception {

		// JWE object from spec, appendix A-1

		String jweString = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." +
			"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" +
			"ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" +
			"Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" +
			"mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" +
			"1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" +
			"6UklfCpIMfIjf7iGdXKHzg." +
			"48V1_ALb6US04U3b." +
			"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" +
			"SdiwkIr3ajwQzaBtQD_A." +
			"XFBoMYUZodetZdvTiFvSkQ";

		JWEObject jweObject = JWEObject.parse(jweString);

		assertEquals(JWEAlgorithm.RSA_OAEP, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, jweObject.getHeader().getEncryptionMethod());

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		RSADecrypter decrypter = new RSADecrypter(PRIVATE_KEY);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		Payload payload = jweObject.getPayload();

		assertEquals("The true sign of intelligence is not knowledge but imagination.", payload.toString());
	}


	public void testCookbookExample()
		throws Exception {
		
		// See http://tools.ietf.org/html/rfc7520#section-5.2
		
		String json = "{" +
			"\"kty\":\"RSA\"," +
			"\"kid\":\"samwise.gamgee@hobbiton.example\"," +
			"\"use\":\"enc\"," +
			"\"n\":\"wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRr" +
			"I4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-Fy" +
			"XJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnk" +
			"Nrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeSt" +
			"sqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M" +
			"5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIU" +
			"e7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBOD" +
			"FskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb" +
			"86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqB" +
			"SAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhO" +
			"OnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDa" +
			"iCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnT" +
			"yC0xhWBlsolZE\"," +
			"\"e\":\"AQAB\"," +
			"\"alg\":\"RSA-OAEP\"," +
			"\"d\":\"n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bx" +
			"cc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq" +
			"-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT" +
			"2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9E" +
			"A-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876" +
			"DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIj" +
			"h1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r" +
			"-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yD" +
			"F-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1L" +
			"oomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W" +
			"_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28" +
			"S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c" +
			"9WsWgRzI-K8gE\"," +
			"\"p\":\"7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKgh" +
			"vM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsY" +
			"a_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3m" +
			"Y46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-" +
			"RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9s" +
			"fbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgP" +
			"gWCv5HoQ\"," +
			"\"q\":\"zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6Zy" +
			"KQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDc" +
			"qssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYG" +
			"RuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJ" +
			"aPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EX" +
			"e2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJ" +
			"JlXXnH8Q\"," +
			"\"dp\":\"19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xn" +
			"x5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQ" +
			"J_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72F" +
			"ZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3i" +
			"XjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGm" +
			"pKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9Lc" +
			"nwwT0jvoQ\"," +
			"\"dq\":\"S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1" +
			"VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM" +
			"1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fg" +
			"dyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrI" +
			"ChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2" +
			"AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iz" +
			"nBNCeOUIQ\"," +
			"\"qi\":\"FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCc" +
			"iRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80" +
			"oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMw" +
			"QqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl" +
			"27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4" +
			"UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq" +
			"8EzqZEKIA\"" +
			"}";
		
		RSAKey jwk = RSAKey.parse(json);
		
		
		String jwe = "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG" +
			"9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0" +
			"." +
			"rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi" +
			"beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu" +
			"cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58" +
			"-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx" +
			"KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK" +
			"IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7" +
			"pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ" +
			"fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3" +
			"8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU" +
			"06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5" +
			"Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR" +
			"s" +
			"." +
			"-nBoKLH0YkLZPSI9" +
			"." +
			"o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR" +
			"L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw" +
			"P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8" +
			"iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML" +
			"7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV" +
			"maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw" +
			"." +
			"UCGiqJxhBI3IFVdPalHHvA";
		
		JWEObject jweObject = JWEObject.parse(jwe);
		
		assertEquals(JWEAlgorithm.RSA_OAEP, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, jweObject.getHeader().getEncryptionMethod());
		assertEquals("samwise.gamgee@hobbiton.example", jweObject.getHeader().getKeyID());
		
		RSADecrypter decrypter = new RSADecrypter(jwk.toRSAPrivateKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		
		jweObject.decrypt(decrypter);
		
		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
	}
	
	
	public void testRSAKeyTooShortToEncryptCEK()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(512);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		
		JWEObject jwe = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256CBC_HS512),
			new Payload("Hello, world!"));
		
		try {
			jwe.encrypt(encrypter);
			fail();
		} catch (JOSEException e) {
			assertEquals("RSA block size exception: The RSA key is too short, try a longer one", e.getMessage());
			assertNotNull(e.getCause());
		}
	}
}