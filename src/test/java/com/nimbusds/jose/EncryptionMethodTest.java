package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the EncryptionMethod class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-15)
 */
public class EncryptionMethodTest extends TestCase {


	public void testCMKLengths() {


		assertEquals(256, EncryptionMethod.A128CBC_HS256.cmkBitLength());

		assertEquals(512, EncryptionMethod.A256CBC_HS512.cmkBitLength());

		assertEquals(128, EncryptionMethod.A128GCM.cmkBitLength());

		assertEquals(256, EncryptionMethod.A256GCM.cmkBitLength());
	}
}
