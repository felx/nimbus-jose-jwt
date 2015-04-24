package com.nimbusds.jose.crypto;


import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;


/**
 * Tests the AES KeyWrap static methods.
 */
public class AESKWTest extends TestCase {


	// From http://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-C
	public void testVectorEncryptCEK()
		throws Exception {

		final byte[] cek = {
			(byte)111, (byte) 27, (byte) 25, (byte) 52, (byte) 66, (byte) 29, (byte) 20, (byte) 78,
			(byte) 92, (byte)176, (byte) 56, (byte)240, (byte) 65, (byte)208, (byte) 82, (byte)112,
			(byte)161, (byte)131, (byte) 36, (byte) 55, (byte)202, (byte)236, (byte)185, (byte)172,
			(byte)129, (byte) 23, (byte)153, (byte)194, (byte)195, (byte) 48, (byte)253, (byte)182 };

		final byte[] kek = {
			(byte)110, (byte)171, (byte)169, (byte) 92, (byte)129, (byte) 92, (byte)109, (byte)117,
			(byte)233, (byte)242, (byte)116, (byte)233, (byte)170, (byte) 14, (byte) 24, (byte) 75 };

		final byte[] encryptedCEK = AESKW.encryptCEK(new SecretKeySpec(cek, "AES"), new SecretKeySpec(kek, "AES"));

		final byte[] expectedEncryptedCEK = {
			(byte) 78, (byte)186, (byte)151, (byte) 59, (byte) 11, (byte)141, (byte) 81, (byte)240,
			(byte)213, (byte)245, (byte) 83, (byte)211, (byte) 53, (byte)188, (byte)134, (byte)188,
			(byte) 66, (byte)125, (byte) 36, (byte)200, (byte)222, (byte)124, (byte)  5, (byte)103,
			(byte)249, (byte) 52, (byte)117, (byte)184, (byte)140, (byte) 81, (byte)246, (byte)158,
			(byte)161, (byte)177, (byte) 20, (byte) 33, (byte)245, (byte) 57, (byte)59,  (byte)4 };

		assertTrue(Arrays.equals(expectedEncryptedCEK, encryptedCEK));
	}


	public void testVectorDecryptCEK()
		throws Exception {

		final byte[] encryptedCEK = {
			(byte) 78, (byte)186, (byte)151, (byte) 59, (byte) 11, (byte)141, (byte) 81, (byte)240,
			(byte)213, (byte)245, (byte) 83, (byte)211, (byte) 53, (byte)188, (byte)134, (byte)188,
			(byte) 66, (byte)125, (byte) 36, (byte)200, (byte)222, (byte)124, (byte)  5, (byte)103,
			(byte)249, (byte) 52, (byte)117, (byte)184, (byte)140, (byte) 81, (byte)246, (byte)158,
			(byte)161, (byte)177, (byte) 20, (byte) 33, (byte)245, (byte) 57, (byte)59,  (byte)4 };

		final byte[] kek = {
			(byte)110, (byte)171, (byte)169, (byte) 92, (byte)129, (byte) 92, (byte)109, (byte)117,
			(byte)233, (byte)242, (byte)116, (byte)233, (byte)170, (byte) 14, (byte) 24, (byte) 75 };

		final SecretKey cek = AESKW.decryptCEK(new SecretKeySpec(kek, "AES"), encryptedCEK);

		final byte[] expectedCEK = {
			(byte)111, (byte) 27, (byte) 25, (byte) 52, (byte) 66, (byte) 29, (byte) 20, (byte) 78,
			(byte) 92, (byte)176, (byte) 56, (byte)240, (byte) 65, (byte)208, (byte) 82, (byte)112,
			(byte)161, (byte)131, (byte) 36, (byte) 55, (byte)202, (byte)236, (byte)185, (byte)172,
			(byte)129, (byte) 23, (byte)153, (byte)194, (byte)195, (byte) 48, (byte)253, (byte)182 };

		assertTrue(Arrays.equals(expectedCEK, cek.getEncoded()));
	}
}
