package com.nimbusds.jose;


import java.text.ParseException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Public / private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK). This
 * class is immutable.
 *
 * <p>Example JSON object representation of a public / private EC JWK:
 * 
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d"   : "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-03-18)
 */
@Immutable
public final class ECKeyPair extends ECPublicKey {
	

	/**
	 * The private 'd' EC coordinate.
	 */
	private final Base64URL d;


	/**
	 * Creates a new public / private Elliptic Curve JSON Web Key (JWK) 
	 * with the specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The 'x' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param y   The 'y' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param d   The 'd' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 * 
	 */
	public ECKeyPair(final Curve crv, final Base64URL x, final Base64URL y, final Base64URL d,
		         final Use use, final Algorithm alg, final String kid) {

		super(crv, x, y, use, alg, kid);

		
		if (d == null) {
			throw new IllegalArgumentException("The d coordinate must not be null");
		}
		
		this.d = d;
	}

	
	/**
	 * Gets the 'd' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'd' coordinate.
	 */
	public Base64URL getD() {

		return d;
	}


	/**
	 * Gets the public Elliptic Curve JWK.
	 *
	 * @return The public Elliptic Curve JWK.
	 */
	public ECPublicKey getECPublicKey() {

		return new ECPublicKey(getCurve(), getX(), getY(), 
			               getKeyUse(), getAlgorithm(), getKeyID());
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		o.put("d", d.toString());
		
		return o;
	}


	/**
	 * Parses a public / private Elliptic Curve JWK from the specified JSON
	 * object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The public / private Elliptic Curve JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        valid Elliptic Curve JWK.
	 */
	public static ECKeyPair parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse the public key parameters first
		ECPublicKey pub = ECPublicKey.parse(jsonObject);

		// Parse the private 'd' parameter
		Base64URL d = new Base64URL(JSONObjectUtils.getString(jsonObject, "d"));

		return new ECKeyPair(pub.getCurve(), pub.getX(), pub.getY(), d,
		                     pub.getKeyUse(), pub.getAlgorithm(), pub.getKeyID());
	}
}
