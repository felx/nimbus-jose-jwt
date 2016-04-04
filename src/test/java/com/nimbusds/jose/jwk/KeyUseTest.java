package com.nimbusds.jose.jwk;


import java.text.ParseException;

import junit.framework.TestCase;


/**
 * Tests the key use enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-04-03
 */
public class KeyUseTest extends TestCase {


	public void testIdentifiers() {

		assertEquals("sig", KeyUse.SIGNATURE.identifier());
		assertEquals("sig", KeyUse.SIGNATURE.toString());

		assertEquals("enc", KeyUse.ENCRYPTION.identifier());
		assertEquals("enc", KeyUse.ENCRYPTION.toString());
	}


	public void testParse()
		throws ParseException {

		assertEquals(KeyUse.SIGNATURE, KeyUse.parse("sig"));
		assertEquals(KeyUse.ENCRYPTION, KeyUse.parse("enc"));
	}


	public void testParseException() {

		try {
			KeyUse.parse("no-such-use");

			fail();

		} catch (ParseException e) {
			// ok
		}
	}


	public void testParseNull()
		throws ParseException {

		assertNull(KeyUse.parse(null));
	}
}
