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

package com.nimbusds.jose.util;


import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.util.Base64;
import net.minidev.json.JSONArray;


/**
 * X.509 certificate chain utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2013-05-29
 */
public class X509CertChainUtils {

	/**
	 * Parses an X.509 certificate chain from the specified JSON array.
	 *
	 * @param jsonArray The JSON array to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate chain.
	 *
	 * @throws ParseException If the X.509 certificate chain couldn't be
	 *                        parsed.
	 */
	public static List<Base64> parseX509CertChain(final JSONArray jsonArray)
		throws ParseException {

		List<Base64> chain = new LinkedList<>();

		for (int i=0; i < jsonArray.size(); i++) {

			Object item = jsonArray.get(i);

			if (item == null) {
				throw new ParseException("The X.509 certificate at position " + i + " must not be null", 0);
			}

			if  (! (item instanceof String)) {
				throw new ParseException("The X.509 certificate at position " + i + " must be encoded as a Base64 string", 0);
			}

			chain.add(new Base64((String)item));
		}

		return chain;
	}

	/**
	 * Prevents public instantiation.
	 */
	private X509CertChainUtils() {}
}