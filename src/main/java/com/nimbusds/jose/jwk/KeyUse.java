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
 * @version 2014-04-02
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
}
