package com.nimbusds.jose.crypto;


import junit.framework.TestCase;

import org.junit.Assert;


/**
 * Tests the authenticated cipher text wrapper.
 *
 * @author Vladimir Dzhuvinov
 * @version 2013-05-07
 */
public class AuthenticatedCipherTextTest extends TestCase {


	public void testRun() {

		byte[] cipherText = {1, 2, 3, 4, 5};
		byte[] authTag = {6, 7, 8, 9, 10};

		AuthenticatedCipherText act = new AuthenticatedCipherText(cipherText, authTag);

		Assert.assertArrayEquals(cipherText, act.getCipherText());

		Assert.assertArrayEquals(authTag, act.getAuthenticationTag());
	}
}