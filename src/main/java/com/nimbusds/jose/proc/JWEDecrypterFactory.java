package com.nimbusds.jose.proc;


import java.security.Key;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEProvider;


/**
 * JSON Web Encryption (JWE) decrypter factory.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-11-16
 */
public interface JWEDecrypterFactory extends JWEProvider {


	/**
	 * Creates a new JWE decrypter for the specified header and key.
	 *
	 * @param header The JWE header. Not {@code null}.
	 * @param key    The key intended to verify the JWS message. Not
	 *               {@code null}.
	 *
	 * @return The JWE decrypter.
	 *
	 * @throws JOSEException If the JWE algorithm / encryption method is
	 *                       not supported or the key type or length
	 *                       doesn't match expected for the JWE algorithm.
	 */
	JWEDecrypter createJWEDecrypter(final JWEHeader header, final Key key)
		throws JOSEException;
}
