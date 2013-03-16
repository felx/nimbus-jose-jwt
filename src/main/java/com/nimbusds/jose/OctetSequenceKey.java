package com.nimbusds.jose;


import java.text.ParseException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.ECKey.Curve;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * {@link KeyType#OCT Symmetric} JSON Web Key (JWK), represented by an octet
 * sequence. This class is immutable.
 *
 * <p>Example JSON object representation of a symmetric JWK:
 *
 * <pre>
 * {
 *   "kty" : "oct",
 *   "alg" : "A128KW",
 *   "k"   : "GawgguFyGrWKav7AX4VKUg"
 * }
 * </pre>
 * 
 * @author Justin Richer
 * @version $version$ (2013-03-15)
 */
@Immutable
public class OctetSequenceKey extends JWK {


	/**
	 * The symmetric key value.
	 */
	private final Base64URL k;

	
	/**
	 * Creates a new symmetric JSON Web Key (JWK) with the specified
	 * parameters.
	 *
	 * @param use The key use. {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 * @param k   The key value. It is represented as the Base64URL 
	 *            encoding of value's big endian representation. Must not 
	 *            be {@code null}.
	 */
	public OctetSequenceKey(final Use use, final Algorithm alg, final String kid, final Base64URL k) {
	
		super(KeyType.OCT, use, alg, kid);

		if (k == null) {
			throw new IllegalArgumentException("Key value must not be null");
		}

		this.k = k;
	}
    

	/**
	 * Returns the value of this symmetric key. It is represented as the 
	 * Base64URL encoding of the coordinate's big endian representation.
	 *
	 * @return The key value. 
	*/
	public Base64URL getKeyValue() {

		return k;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Append key value
		o.put("k", k.toString());
		
		return o;
	}
	
	/**
	 * Parses a symmetric key from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   @code null}.
	 *
	 * @return The symmetric Key.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to 
	 *                        valid symmetric JWK.
	 */
	public static OctetSequenceKey parse(final JSONObject jsonObject) 
		throws ParseException {

		// Parse the mandatory parameters first
		KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));
		Base64URL k = new Base64URL(JSONObjectUtils.getString(jsonObject, "k"));
		Base64URL y = new Base64URL(JSONObjectUtils.getString(jsonObject, "y"));

		// Get optional key use
		Use use = JWK.parseKeyUse(jsonObject);

		// Get optional intended algorithm
		Algorithm alg = JWK.parseAlgorithm(jsonObject);

		// Get optional key ID
		String kid = JWK.parseKeyID(jsonObject);

		// Check key type
		if (kty != KeyType.OCT) {
			throw new ParseException("The key type \"kty\" must be oct", 0);
		}

		return new OctetSequenceKey(use, alg, kid, k);
	}
}
