/**
 * 
 */
package com.nimbusds.jose;

import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.ECKey.Curve;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * 
 * Key type for storing symmetric keys. This class is immutable.
 * 
 * @author Justin Richer
 *
 */
public class OctetSequenceKey extends JWK {

	/**
	 * The private key value.
	 */
	private final Base64URL k;
	
	/**
	 * @param kty
	 * @param use
	 * @param alg
	 * @param kid
	 */
    public OctetSequenceKey(final Use use, final Algorithm alg, final String kid, final Base64URL k) {
	    super(KeyType.OCT, use, alg, kid);

	    if (k == null) {
	    	throw new IllegalArgumentException("Key value must not be null");
	    }
	    
	    this.k = k;
    }
    
    /**
     * 
     * @return The private key value. It is 
	 *         represented as the Base64URL encoding of the coordinate's 
	 *         big endian representation.
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
	 * Parse the Octet Sequence Key from the JSON representation.
	 * @param jsonObject the JSON objet to parse.
	 * @return the JWK
	 * @throws ParseException if the JSON object couldn't be parsed into a JWK.
	 */
	public static OctetSequenceKey parse(final JSONObject jsonObject) throws ParseException {
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
