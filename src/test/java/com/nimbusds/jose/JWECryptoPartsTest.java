package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the JWE crypto parts class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-11
 */
public class JWECryptoPartsTest extends TestCase {


	public void testConstructorWithoutHeader() {

		JWECryptoParts p = new JWECryptoParts(
			new Base64URL("abc"),
			new Base64URL("def"),
			new Base64URL("ghi"),
			new Base64URL("jkl")
		);


		assertNull(p.getHeader());
		assertEquals("abc", p.getEncryptedKey().toString());
		assertEquals("def", p.getInitializationVector().toString());
		assertEquals("ghi", p.getCipherText().toString());
		assertEquals("jkl", p.getAuthenticationTag().toString());


		p = new JWECryptoParts(null, null, new Base64URL("abc"), null);

		assertNull(p.getHeader());
		assertNull(p.getEncryptedKey());
		assertNull(p.getInitializationVector());
		assertEquals("abc", p.getCipherText().toString());
		assertNull(p.getAuthenticationTag());
	}


	public void testConstructorWithHeader() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

		JWECryptoParts p = new JWECryptoParts(
			header,
			new Base64URL("abc"),
			new Base64URL("def"),
			new Base64URL("ghi"),
			new Base64URL("jkl")
		);

		assertEquals(header, p.getHeader());
		assertEquals("abc", p.getEncryptedKey().toString());
		assertEquals("def", p.getInitializationVector().toString());
		assertEquals("ghi", p.getCipherText().toString());
		assertEquals("jkl", p.getAuthenticationTag().toString());

		p = new JWECryptoParts(null, null, null, new Base64URL("abc"), null);

		assertNull(p.getHeader());
		assertNull(p.getEncryptedKey());
		assertNull(p.getInitializationVector());
		assertEquals("abc", p.getCipherText().toString());
		assertNull(p.getAuthenticationTag());
	}
}
