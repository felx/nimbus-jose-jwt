/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.ECKey;


/**
 * Tests EC JWS verification. Uses test vectors from the JOSE cookbook.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-22
 */
public class ECDSACookbookTest extends TestCase {


	public void testES512Verify()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-4.3

		String json = "{"+
			"\"kty\":\"EC\","+
			"\"kid\":\"bilbo.baggins@hobbiton.example\","+
			"\"use\":\"sig\","+
			"\"crv\":\"P-521\","+
			"\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"+
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","+
			"\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","+
			"\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"+
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""+
			"}";

		ECKey jwk = ECKey.parse(json);

		String jws = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX"+
			"hhbXBsZSJ9"+
			"."+
			"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH"+
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk"+
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm"+
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"+
			"."+
			"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb"+
			"u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv"+
			"AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

		JWSObject jwsObject = JWSObject.parse(jws);

		assertEquals(JWSAlgorithm.ES512, jwsObject.getHeader().getAlgorithm());
		assertEquals("bilbo.baggins@hobbiton.example", jwsObject.getHeader().getKeyID());

		JWSVerifier verifier = new ECDSAVerifier(jwk);

		assertTrue(jwsObject.verify(verifier));

		assertEquals("SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4", jwsObject.getPayload().toBase64URL().toString());
	}
}
