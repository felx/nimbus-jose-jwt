package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the EncryptionMethod class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-10-14
 */
public class EncryptionMethodTest extends TestCase {


	public void testCMKLengths() {

		assertEquals(256, EncryptionMethod.A128CBC_HS256.cekBitLength());
		assertEquals(384, EncryptionMethod.A192CBC_HS384.cekBitLength());
		assertEquals(512, EncryptionMethod.A256CBC_HS512.cekBitLength());

		assertEquals(128, EncryptionMethod.A128GCM.cekBitLength());
		assertEquals(192, EncryptionMethod.A192GCM.cekBitLength());
		assertEquals(256, EncryptionMethod.A256GCM.cekBitLength());

		assertEquals(256, EncryptionMethod.A128CBC_HS256_DEPRECATED.cekBitLength());
		assertEquals(512, EncryptionMethod.A256CBC_HS512_DEPRECATED.cekBitLength());
	}


	public void testAESCBCHMACFamily() {

		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(EncryptionMethod.A256CBC_HS512));
		assertEquals(3, EncryptionMethod.Family.AES_CBC_HMAC_SHA.size());
	}


	public void testAESGCMFamily() {

		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A256GCM));
		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A192GCM));
		assertTrue(EncryptionMethod.Family.AES_GCM.contains(EncryptionMethod.A256GCM));
		assertEquals(3, EncryptionMethod.Family.AES_GCM.size());
	}
}
