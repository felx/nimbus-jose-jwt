package com.nimbusds.jose.crypto;


import java.math.BigInteger;

import java.security.KeyFactory;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests RS256 JWS signing and verfication. Uses test vectors from JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
public class RSASSATest extends TestCase {


	private final static byte[] mod = { (byte) 161, (byte) 248, (byte)  22, (byte)  10, (byte) 226, (byte) 227, (byte) 201, (byte) 180,
                                            (byte) 101, (byte) 206, (byte) 141, (byte)  45, (byte) 101, (byte)  98, (byte)  99, (byte)  54, 
					    (byte)  43, (byte) 146, (byte) 125, (byte) 190, (byte)  41, (byte) 225, (byte) 240, (byte)  36, 
					    (byte) 119, (byte) 252, (byte)  22, (byte)  37, (byte) 204, (byte) 144, (byte) 161, (byte)  54, 
					    (byte) 227, (byte) 139, (byte) 217, (byte)  52, (byte) 151, (byte) 197, (byte) 182, (byte) 234, 
					    (byte)  99, (byte) 221, (byte) 119, (byte)  17, (byte) 230, (byte) 124, (byte) 116, (byte)  41, 
					    (byte) 249, (byte)  86, (byte) 176, (byte) 251, (byte) 138, (byte) 143, (byte)   8, (byte) 154, 
					    (byte) 220, (byte)  75, (byte) 105, (byte) 137, (byte)  60, (byte) 193, (byte)  51, (byte)  63, 
					    (byte)  83, (byte) 237, (byte) 208, (byte)  25, (byte) 184, (byte) 119, (byte) 132, (byte)  37, 
					    (byte)  47, (byte) 236, (byte) 145, (byte)  79, (byte) 228, (byte) 133, (byte) 119, (byte) 105,
					    (byte)  89, (byte)  75, (byte) 234, (byte)  66, (byte) 128, (byte) 211, (byte)  44, (byte)  15, 
					    (byte)  85, (byte) 191, (byte)  98, (byte) 148, (byte)  79, (byte)  19, (byte)   3, (byte) 150, 
					    (byte) 188, (byte) 110, (byte) 155, (byte) 223, (byte) 110, (byte) 189, (byte) 210, (byte) 189, 
					    (byte) 163, (byte) 103, (byte) 142, (byte) 236, (byte) 160, (byte) 198, (byte) 104, (byte) 247, 
					    (byte)   1, (byte) 179, (byte) 141, (byte) 191, (byte) 251, (byte)  56, (byte) 200, (byte)  52, 
					    (byte)  44, (byte) 226, (byte) 254, (byte) 109, (byte)  39, (byte) 250, (byte) 222, (byte)  74, 
					    (byte)  90, (byte)  72, (byte) 116, (byte) 151, (byte) 157, (byte) 212, (byte) 185, (byte) 207, 
					    (byte) 154, (byte) 222, (byte) 196, (byte) 199, (byte)  91, (byte)   5, (byte) 133, (byte)  44, 
					    (byte)  44, (byte)  15, (byte)  94, (byte) 248, (byte) 165, (byte) 193, (byte) 117, (byte)   3,
					    (byte) 146, (byte) 249, (byte)  68, (byte) 232, (byte) 237, (byte) 100, (byte) 193, (byte)  16, 
					    (byte) 198, (byte) 182, (byte)  71, (byte)  96, (byte) 154, (byte) 164, (byte) 120, (byte)  58, 
					    (byte) 235, (byte) 156, (byte) 108, (byte) 154, (byte) 215, (byte)  85, (byte)  49, (byte)  48, 
					    (byte)  80, (byte)  99, (byte) 139, (byte) 131, (byte) 102, (byte)  92, (byte) 111, (byte) 111, 
					    (byte) 122, (byte) 130, (byte) 163, (byte) 150, (byte) 112, (byte)  42, (byte)  31, (byte) 100, 
					    (byte)  27, (byte) 130, (byte) 211, (byte) 235, (byte) 242, (byte)  57, (byte)  34, (byte)  25, 
					    (byte)  73, (byte)  31, (byte) 182, (byte) 134, (byte) 135, (byte)  44, (byte)  87, (byte)  22, 
					    (byte) 245, (byte)  10, (byte) 248, (byte)  53, (byte) 141, (byte) 154, (byte) 139, (byte) 157, 
					    (byte)  23, (byte) 195, (byte)  64, (byte) 114, (byte) 143, (byte) 127, (byte) 135, (byte) 216,
					    (byte) 154, (byte)  24, (byte) 216, (byte) 252, (byte) 171, (byte) 103, (byte) 173, (byte) 132, 
					    (byte)  89, (byte)  12, (byte)  46, (byte) 207, (byte) 117, (byte) 147, (byte)  57, (byte)  54, 
					    (byte)  60, (byte)   7, (byte)   3, (byte)  77, (byte) 111, (byte)  96, (byte) 111, (byte) 158, 
					    (byte)  33, (byte) 224, (byte)  84, (byte)  86, (byte) 202, (byte) 229, (byte) 233, (byte) 161 };

		  
	private static final byte[] exp= { 1, 0, 1 };
	
	
	private static final byte[] modPriv = { (byte)  18, (byte) 174, (byte) 113, (byte) 164, (byte) 105, (byte) 205, (byte)  10, (byte)  43,
	                                        (byte) 195, (byte) 126, (byte)  82, (byte) 108, (byte)  69, (byte)   0, (byte)  87, (byte)  31, 
						(byte)  29, (byte)  97, (byte) 117, (byte)  29, (byte) 100, (byte) 233, (byte)  73, (byte) 112, 
						(byte) 123, (byte)  98, (byte)  89, (byte)  15, (byte) 157, (byte)  11, (byte) 165, (byte) 124, 
						(byte) 150, (byte)  60, (byte)  64, (byte)  30, (byte)  63, (byte) 207, (byte)  47, (byte)  44, 
						(byte) 211, (byte) 189, (byte) 236, (byte) 136, (byte) 229, (byte)   3, (byte) 191, (byte) 198, 
						(byte)  67, (byte) 155, (byte)  11, (byte)  40, (byte) 200, (byte)  47, (byte) 125, (byte)  55, 
						(byte) 151, (byte) 103, (byte)  31, (byte)  82, (byte)  19, (byte) 238, (byte) 216, (byte) 193, 
						(byte)  90, (byte)  37, (byte) 216, (byte) 213, (byte) 206, (byte) 160, (byte)   2, (byte)  94, 
						(byte) 227, (byte) 171, (byte)  46, (byte) 139, (byte) 127, (byte) 121, (byte)  33, (byte) 111,
						(byte) 198, (byte)  59, (byte) 234, (byte)  86, (byte)  39, (byte)  83, (byte) 180, (byte)  6, 
						(byte)  68, (byte) 198, (byte) 161, (byte)  81, (byte)  39, (byte) 217, (byte) 178, (byte) 149, 
						(byte)  69, (byte)  64, (byte) 160, (byte) 187, (byte) 225, (byte) 163, (byte)   5, (byte)  86, 
						(byte) 152, (byte)  45, (byte)  78, (byte) 159, (byte) 222, (byte)  95, (byte) 100, (byte)  37, 
						(byte) 241, (byte)  77, (byte)  75, (byte) 113, (byte)  52, (byte)  65, (byte) 181, (byte)  93, 
						(byte) 199, (byte)  59, (byte) 155, (byte)  74, (byte) 237, (byte) 204, (byte) 146, (byte) 172, 
						(byte) 227, (byte) 146, (byte) 126, (byte)  55, (byte) 245, (byte) 125, (byte)  12, (byte) 253, 
						(byte)  94, (byte) 117, (byte) 129, (byte) 250, (byte)  81, (byte)  44, (byte) 143, (byte)  73, 
						(byte)  97, (byte) 169, (byte) 235, (byte)  11, (byte) 128, (byte) 248, (byte) 168, (byte)   7,
						(byte)  70, (byte) 114, (byte) 138, (byte)  85, (byte) 255, (byte)  70, (byte)  71, (byte)  31, 
						(byte)  52, (byte)  37, (byte) 6,   (byte)  59, (byte) 157, (byte)  83, (byte) 100, (byte)  47, 
						(byte)  94, (byte) 222, (byte)  30, (byte) 132, (byte) 214, (byte)  19, (byte)   8, (byte)  26, 
						(byte) 250, (byte)  92, (byte)  34, (byte) 208, (byte)  81, (byte)  40, (byte)  91, (byte) 214, 
						(byte)  59, (byte) 148, (byte)  59, (byte)  86, (byte)  93, (byte) 137, (byte) 138, (byte)   5, 
						(byte) 104, (byte)  84, (byte)  19, (byte) 229, (byte)  60, (byte)  60, (byte) 108, (byte) 101, 
						(byte)  37, (byte) 255, (byte)  31, (byte) 227, (byte)  78, (byte)  61, (byte) 220, (byte) 112, 
						(byte) 240, (byte) 213, (byte) 100, (byte)  80, (byte) 253, (byte) 164, (byte) 139, (byte) 161, 
						(byte)  46, (byte)  16, (byte)  78, (byte) 157, (byte) 235, (byte) 159, (byte) 184, (byte)  24,
						(byte) 129, (byte) 225, (byte) 196, (byte) 189, (byte) 242, (byte)  93, (byte) 146, (byte)  71, 
						(byte) 244, (byte)  80, (byte) 200, (byte) 101, (byte) 146, (byte) 121, (byte) 104, (byte) 231, 
						(byte) 115, (byte)  52, (byte) 244, (byte)  65, (byte)  79, (byte) 117, (byte) 167, (byte)  80, 
						(byte) 225, (byte)  57, (byte)  84, (byte) 110, (byte)  58, (byte) 138, (byte) 115, (byte) 157 };


	private static RSAPublicKey publicKey;
	
	
	private static RSAPrivateKey privateKey;


	static {
	
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, exp));
			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, mod), new BigInteger(1, modPriv));
	
			publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		
		} catch (Exception e) {
	
			System.err.println(e);
		}
	}
	
	
	private static final Base64URL b64header = new Base64URL("eyJhbGciOiJSUzI1NiJ9");
	
	
	private static final Payload payload = new Payload(new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
								         "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));
	
	
	private static final byte[] signable = new String("eyJhbGciOiJSUzI1NiJ9" +
	                                                  "." +
							  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
							  "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();
	
	
	private static final Base64URL b64sig = new Base64URL("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
	                                                      "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
							      "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
							      "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
							      "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
							      "p0igcN_IoypGlUPQGe77Rw");
	
	
	
	public void testSignAndVerify()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		assertEquals("RS256 alg check", JWSAlgorithm.RS256, header.getAlgorithm());
		
		JWSObject jwsObject = new JWSObject(header, payload);
		
		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());
		
		
		RSASSASigner signer = new RSASSASigner(privateKey);
		assertNotNull("Private key check", signer.getPrivateKey());
		assertEquals(3, signer.supportedAlgorithms().size());
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS512));
		
		jwsObject.sign(signer);
		
		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
		
		
		RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
		assertNotNull("Public key check", verifier.getPublicKey());
		assertEquals(3, signer.supportedAlgorithms().size());
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.RS512));
		
		boolean verified = jwsObject.verify(verifier);
		
		assertTrue("Verified signature", verified);
		
		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}
	
	
	public void testSignWithReadyVector()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		JWSSigner signer = new RSASSASigner(privateKey);
		
		Base64URL b64sigComputed = signer.sign(header, signable);
		
		assertEquals("Signature check", b64sig, b64sigComputed);
	}
	
	
	public void testVerifyWithReadyVector()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		
		boolean verified = verifier.verify(header, signable, b64sig);
		
		assertTrue("Signature check", verified);
	}
	
	
	public void testParseAndVerify()
		throws Exception {
	
		String s = b64header.toString() + "." + payload.toBase64URL().toString() + "." + b64sig.toString();
		
		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());
		
		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
		
		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		
		boolean verified = jwsObject.verify(verifier);
		
		assertTrue("Signature check", verified);
		
		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}
}
