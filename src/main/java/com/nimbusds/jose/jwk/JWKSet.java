package com.nimbusds.jose.jwk;


import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import org.apache.commons.io.FileUtils;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.URLUtils;


/**
 * JSON Web Key (JWK) set. Represented by a JSON object that contains an array
 * of {@link JWK JSON Web Keys} (JWKs) as the value of its "keys" member.
 * Additional (custom) members of the JWK Set JSON object are also supported.
 *
 * <p>Example JSON Web Key (JWK) set:
 *
 * <pre>
 * {
 *   "keys" : [ { "kty" : "EC",
 *                "crv" : "P-256",
 *                "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *                "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *                "use" : "enc",
 *                "kid" : "1" },
 *
 *              { "kty" : "RSA",
 *                "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *                         4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *                         tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *                         QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *                         SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *                         w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *                "e"   : "AQAB",
 *                "alg" : "RS256",
 *                "kid" : "2011-04-29" } ]
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-12-14
 */
public class JWKSet {


	/**
	 * The MIME type of JWK set objects: 
	 * {@code application/jwk-set+json; charset=UTF-8}
	 */
	public static final String MIME_TYPE = "application/jwk-set+json; charset=UTF-8";


	/**
	 * The JWK list.
	 */
	private final List<JWK> keys = new LinkedList<>();


	/**
	 * Additional custom members.
	 */
	private final Map<String,Object> customMembers = new HashMap<>();


	/**
	 * Creates a new empty JSON Web Key (JWK) set.
	 */
	public JWKSet() {

		// Nothing to do
	}


	/**
	 * Creates a new JSON Web Key (JWK) set with a single key.
	 *
	 * @param key The JWK. Must not be {@code null}.
	 */
	public JWKSet(final JWK key) {

		if (key == null) {
			throw new IllegalArgumentException("The JWK must not be null");
		}

		keys.add(key);
	}


	/**
	 * Creates a new JSON Web Key (JWK) set with the specified keys.
	 *
	 * @param keys The JWK list. Must not be {@code null}.
	 */
	public JWKSet(final List<JWK> keys) {

		if (keys == null) {
			throw new IllegalArgumentException("The JWK list must not be null");
		}

		this.keys.addAll(keys);
	}


	/**
	 * Creates a new JSON Web Key (JWK) set with the specified keys and
	 * additional custom members.
	 *
	 * @param keys          The JWK list. Must not be {@code null}.
	 * @param customMembers The additional custom members. Must not be
	 *                      {@code null}.
	 */
	public JWKSet(final List<JWK> keys, final Map<String,Object> customMembers) {

		if (keys == null) {
			throw new IllegalArgumentException("The JWK list must not be null");
		}

		this.keys.addAll(keys);

		this.customMembers.putAll(customMembers);
	}


	/**
	 * Gets the keys (ordered) of this JSON Web Key (JWK) set.
	 *
	 * @return The keys, empty list if none.
	 */
	public List<JWK> getKeys() {

		return keys;
	}

	
	/**
	 * Gets the key from this JSON Web Key (JWK) set as identified by its 
	 * Key ID (kid) member.
	 * 
	 * <p>If more than one key exists in the JWK Set with the same 
	 * identifier, this function returns only the first one in the set.
	 *
	 * @param kid They key identifier.
	 *
	 * @return The key identified by {@code kid} or {@code null} if no key 
	 *         exists.
	 */
	public JWK getKeyByKeyId(String kid) {
		
		for (JWK key : getKeys()) {
	        
	        	if (key.getKeyID() != null && key.getKeyID().equals(kid)) {
	        		return key;
	        	}
        	}
		
		// no key found
		return null;
	}


	/**
	 * Gets the additional custom members of this JSON Web Key (JWK) set.
	 *
	 * @return The additional custom members, empty map if none.
	 */
	public Map<String,Object> getAdditionalMembers() {

		return customMembers;
	}


	/**
	 * Returns a copy of this JSON Web Key (JWK) set with all private keys
	 * and parameters removed.
	 *
	 * @return A copy of this JWK set with all private keys and parameters
	 *         removed.
	 */
	public JWKSet toPublicJWKSet() {

		List<JWK> publicKeyList = new LinkedList<>();

		for (JWK key: keys) {

			JWK publicKey = key.toPublicJWK();

			if (publicKey != null) {
				publicKeyList.add(publicKey);
			}
		}

		return new JWKSet(publicKeyList, customMembers);
	}


	/**
	 * Returns the JSON object representation of this JSON Web Key (JWK) 
	 * set. Private keys and parameters will be omitted from the output.
	 * Use the alternative {@link #toJSONObject(boolean)} method if you
	 * wish to include them.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		return toJSONObject(true);
	}


	/**
	 * Returns the JSON object representation of this JSON Web Key (JWK) 
	 * set.
	 *
	 * @param publicKeysOnly Controls the inclusion of private keys and
	 *                       parameters into the output JWK members. If
	 *                       {@code true} private keys and parameters will
	 *                       be omitted. If {@code false} all available key
	 *                       parameters will be included.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject(final boolean publicKeysOnly) {

		JSONObject o = new JSONObject(customMembers);

		JSONArray a = new JSONArray();

		for (JWK key: keys) {

			if (publicKeysOnly) {

				// Try to get public key, then serialise
				JWK publicKey = key.toPublicJWK();

				if (publicKey != null) {
					a.add(publicKey.toJSONObject());
				}
			} else {

				a.add(key.toJSONObject());
			}
		}

		o.put("keys", a);

		return o;
	}


	/**
	 * Returns the JSON object string representation of this JSON Web Key
	 * (JWK) set.
	 *
	 * @return The JSON object string representation.
	 */
	@Override
	public String toString() {

		return toJSONObject().toString();
	}


	/**
	 * Parses the specified string representing a JSON Web Key (JWK) set.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}


	/**
	 * Parses the specified JSON object representing a JSON Web Key (JWK) 
	 * set.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet parse(final JSONObject json)
		throws ParseException {

		JSONArray keyArray = JSONObjectUtils.getJSONArray(json, "keys");

		List<JWK> keys = new LinkedList<>();

		for (int i=0; i < keyArray.size(); i++) {

			if (! (keyArray.get(i) instanceof JSONObject)) {
				throw new ParseException("The \"keys\" JSON array must contain JSON objects only", 0);
			}

			JSONObject keyJSON = (JSONObject)keyArray.get(i);

			try {
				keys.add(JWK.parse(keyJSON));

			} catch (ParseException e) {

				throw new ParseException("Invalid JWK at position " + i + ": " + e.getMessage(), 0);
			}
		}

		// Parse additional custom members
		JWKSet jwkSet = new JWKSet(keys);

		for (Map.Entry<String,Object> entry: json.entrySet()) {

			if (entry.getKey() == null || entry.getKey().equals("keys")) {
				continue;
			}

			jwkSet.getAdditionalMembers().put(entry.getKey(), entry.getValue());
		}

		return jwkSet;
	}


	/**
	 * Loads a JSON Web Key (JWK) set from the specified file.
	 *
	 * @param file The JWK set file. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet load(final File file)
		throws IOException, ParseException {

		return parse(FileUtils.readFileToString(file));
	}


	/**
	 * Loads a JSON Web Key (JWK) set from the specified URL.
	 *
	 * @param url            The JWK set URL. Must not be {@code null}.
	 * @param connectTimeout The URL connection timeout, in milliseconds.
	 *                       If zero no (infinite) timeout.
	 * @param readTimeout    The URL read timeout, in milliseconds. If zero
	 *                       no (infinite) timeout.
	 * @param sizeLimit      The read size limit, in bytes. If negative no
	 *                       limit.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet load(final URL url,
				  final int connectTimeout,
				  final int readTimeout,
				  final int sizeLimit)
		throws IOException, ParseException {

		return parse(URLUtils.read(url, connectTimeout, readTimeout, sizeLimit));
	}


	/**
	 * Loads a JSON Web Key (JWK) set from the specified URL.
	 *
	 * @param url The JWK set URL. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet load(final URL url)
		throws IOException, ParseException {

		return parse(URLUtils.read(url, 0, 0, -1));
	}
}
