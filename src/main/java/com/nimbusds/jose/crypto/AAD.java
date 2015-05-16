package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;


/**
 * Additional authenticated data (AAD).
 *
 * <p>See draft-ietf-jose-json-web-encryption-40, section 5.1, point 14.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-14)
 */
class AAD {


	// TODO WITH TEST
	public static byte[] compute(final JWEHeader jweHeader) {

		return compute(jweHeader.toBase64URL());
	}



	public static byte[] compute(final Base64URL encodedJWEHeader) {

		return encodedJWEHeader.toString().getBytes(Charset.forName("ASCII"));
	}
}
