package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;


/**
 * Tests RSAES OAEP JWE encryption and decryption. Uses test RSA keys from the 
 * JWE spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-29)
 */
public class RSA_OAEPTest extends TestCase {


	private final static byte[] mod = { 
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


	private static final byte[] exp= { 1, 0, 1 };


	private static final byte[] modPriv = { 
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


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new RSAEncrypter(publicKey);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new RSADecrypter(privateKey);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new RSAEncrypter(publicKey);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new RSADecrypter(privateKey);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}

	
	public void testDecryptWith256GCM()
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

		JWEDecrypter decrypter = new RSADecrypter(privateKey);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		Payload payload = jweObject.getPayload();

		assertEquals("The true sign of intelligence is not knowledge but imagination.", payload.toString());
	}
}