package com.nimbusds.jose.crypto;


import junit.framework.TestCase;

import org.junit.Assert;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the HMAC helper class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-10)
 */
public class HMACTest extends TestCase {


	public void testWithVector()
		throws Exception {

		// Vectors from http://openidtest.uninett.no/jwt#

		byte[] msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUub3JnIiwidHlwIjoiSldUIn0".getBytes("UTF-8");

		byte[] mac = new Base64URL("eagkgLML8Ccrn4eIvidX4a10JBE4Q3eaOAf4Blj9P4c").decode();

		byte[] key = "1879197b29d8ec57".getBytes("UTF-8");


		byte[] computedMac = HMAC.compute("HMACSHA256", key, msg);

		assertEquals(computedMac.length, mac.length);
		Assert.assertArrayEquals(mac, computedMac);
	}
}
