package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-04)
 */
public class JWEObjectTest extends TestCase {


	public void testMIMETypes()
		throws Exception {

		assertTrue(JWEObject.MIME_TYPE_COMPACT.match("application/jwe"));
		assertTrue(JWEObject.MIME_TYPE_COMPACT.getParameterList().get("charset").equalsIgnoreCase("UTF-8"));
		assertEquals(1, JWEObject.MIME_TYPE_COMPACT.getParameterList().size());

		assertTrue(JWEObject.MIME_TYPE_JS.match("application/jwe-js"));
		assertTrue(JWEObject.MIME_TYPE_JS.getParameterList().get("charset").equalsIgnoreCase("UTF-8"));
		assertEquals(1, JWEObject.MIME_TYPE_JS.getParameterList().size());
	}


	public void testBase64URLConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, 
			                         EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jwe = new JWEObject(firstPart, secondPart,
				thirdPart, fourthPart, 
				fifthPart);

		assertEquals(firstPart, jwe.getHeader().toBase64URL());
		assertEquals(secondPart, jwe.getEncryptedKey());
		assertEquals(thirdPart, jwe.getInitializationVector());
		assertEquals(fourthPart, jwe.getCipherText());
		assertEquals(fifthPart, jwe.getIntegrityValue());

		assertEquals(firstPart.toString() + ".abc.def.ghi.jkl", jwe.serialize());
		assertEquals(firstPart.toString() + ".abc.def.ghi.jkl", jwe.getParsedString());

		assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
	}
}