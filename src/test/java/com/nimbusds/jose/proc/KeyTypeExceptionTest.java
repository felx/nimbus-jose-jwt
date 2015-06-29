package com.nimbusds.jose.proc;


import junit.framework.TestCase;

import com.nimbusds.jose.KeyTypeException;


/**
 * Key type exception test.
 */
public class KeyTypeExceptionTest extends TestCase {


	public void testMessage() {

		KeyTypeException e = new KeyTypeException(java.security.interfaces.RSAPublicKey.class);

		assertEquals("Invalid key: Must be an instance of interface java.security.interfaces.RSAPublicKey", e.getMessage());
	}
}
