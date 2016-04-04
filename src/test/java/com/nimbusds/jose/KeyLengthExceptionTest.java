package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the key length exception.
 */
public class KeyLengthExceptionTest extends TestCase {


	public void testMessageConstructor() {

		KeyLengthException e = new KeyLengthException("abc");

		assertEquals("abc", e.getMessage());
		assertEquals(0, e.getExpectedKeyLength());
		assertNull(e.getAlgorithm());
	}


	public void testDetailConstructor() {

		KeyLengthException e = new KeyLengthException(128, EncryptionMethod.A128GCM);

		assertEquals("The expected key length is 128 bits (for A128GCM algorithm)", e.getMessage());
		assertEquals(128, e.getExpectedKeyLength());
		assertEquals(EncryptionMethod.A128GCM, e.getAlgorithm());
	}
}
