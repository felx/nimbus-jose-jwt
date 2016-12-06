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

package com.nimbusds.jose.jwk;


import java.security.cert.X509Certificate;
import java.text.ParseException;


/**
 * Enumeration of public key uses. Represents the {@code use} parameter in a
 * JSON Web Key (JWK).
 *
 * <p>Public JWK use values:
 *
 * <ul>
 *     <li>{@link #SIGNATURE sig}
 *     <li>{@link #ENCRYPTION enc}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-12-06
 */
public enum KeyUse {


	/**
	 * Signature.
	 */
	SIGNATURE("sig"),


	/**
	 * Encryption.
	 */
	ENCRYPTION("enc");


	/**
	 * The public key use identifier.
	 */
	private final String identifier;


	/**
	 * Creates a new public key use with the specified identifier.
	 *
	 * @param identifier The public key use identifier. Must not be
	 *                   {@code null}.
	 */
	KeyUse(final String identifier) {

		if (identifier == null)
			throw new IllegalArgumentException("The key use identifier must not be null");

		this.identifier = identifier;
	}


	/**
	 * Returns the identifier of this public key use.
	 *
	 * @return The identifier.
	 */
	public String identifier() {

		return identifier;
	}


	/**
	 * @see #identifier()
	 */
	@Override
	public String toString() {

		return identifier();
	}


	/**
	 * Parses a public key use from the specified JWK {@code use} parameter
	 * value.
	 *
	 * @param s The string to parse. May be {@code null}.
	 *
	 * @return The public key use, {@code null} if none.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        public key use.
	 */
	public static KeyUse parse(final String s)
		throws ParseException {

		if (s == null) {
			return null;
		}

		for (KeyUse use: KeyUse.values()) {

			if (s.equals(use.identifier)) {
				return use;
			}
		}

		throw new ParseException("Invalid JWK use: " + s, 0);
	}
	
	
	/**
	 * Infers the public key use of the specified X.509 certificate. Note
	 * that there is no standard algorithm for mapping PKIX key usage to
	 * JWK use. See RFC 2459, section 4.2.1.3, as well as the underlying
	 * code for the chosen algorithm to infer JWK use.
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return The public key use, {@code null} if the key use couldn't be
	 *         reliably determined.
	 */
	public static KeyUse from(final X509Certificate cert) {
		
		if (cert.getKeyUsage() == null) {
			return null;
		}
		
		// nonRepudiation
		if (cert.getKeyUsage()[1]) {
			return SIGNATURE;
		}
		
		// digitalSignature && keyEncipherment
		// (e.g. RSA TLS certificate for authenticated encryption)
		if (cert.getKeyUsage()[0] && cert.getKeyUsage()[2]) {
			return KeyUse.ENCRYPTION;
		}
		
		// digitalSignature && keyAgreement
		// (e.g. EC TLS certificate for authenticated encryption)
		if (cert.getKeyUsage()[0] && cert.getKeyUsage()[4]) {
			return KeyUse.ENCRYPTION;
		}
		
		// keyEncipherment || dataEncipherment || keyAgreement
		if (cert.getKeyUsage()[2] || cert.getKeyUsage()[3] || cert.getKeyUsage()[4]) {
			return ENCRYPTION;
		}
		
		// keyCertSign || cRLSign
		if (cert.getKeyUsage()[5] || cert.getKeyUsage()[6]) {
			return SIGNATURE;
		}
		
		return null;
	}
}
