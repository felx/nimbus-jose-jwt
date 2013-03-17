package com.nimbusds.jose;


import java.text.ParseException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Public {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK). This class is 
 * immutable.
 *
 * <p>Example JSON object representation of a public EC JWK:
 * 
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-03-17)
 */
@Immutable
public class ECPublicKey extends JWK {


	/**
	 * The curve name.
	 */
	private final Curve crv;


	/**
	 * The 'x' EC coordinate.
	 */
	private final Base64URL x;


	/**
	 * The 'y' EC coordinate.
	 */
	private final Base64URL y;


	/**
	 * Creates a new public Elliptic Curve JSON Web Key (JWK) with the 
	 * specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The 'x' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param y   The 'y' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	public ECPublicKey(final Curve crv, final Base64URL x, final Base64URL y, 
		           final Use use, final Algorithm alg, final String kid) {

		super(KeyType.EC, use, alg, kid);


		if (crv == null) {
			throw new IllegalArgumentException("The curve must not be null");
		}

		this.crv = crv;


		if (x == null) {
			throw new IllegalArgumentException("The x coordinate must not be null");
		}

		this.x = x;


		if (y == null) {
			throw new IllegalArgumentException("The y coordinate must not be null");
		}

		this.y = y;
	}


	/**
	 * Gets the cryptographic curve.
	 *
	 * @return The cryptographic curve.
	 */
	public Curve getCurve() {

		return crv;
	}


	/**
	 * Gets the 'x' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'x' coordinate.
	 */
	public Base64URL getX() {

		return x;
	}


	/**
	 * Gets the 'y' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'y' coordinate.
	 */
	public Base64URL getY() {

		return y;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Append EC specific attributes
		o.put("crv", crv.toString());
		o.put("x", x.toString());
		o.put("y", y.toString());
		
		return o;
	}


	/**
	 * Parses a public Elliptic Curve JWK from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The public Elliptic Curve JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        public Elliptic Curve JWK.
	 */
	public static ECPublicKey parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse the mandatory parameters first
		KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));
		Curve crv = Curve.parse(JSONObjectUtils.getString(jsonObject, "crv"));
		Base64URL x = new Base64URL(JSONObjectUtils.getString(jsonObject, "x"));
		Base64URL y = new Base64URL(JSONObjectUtils.getString(jsonObject, "y"));
		
		// Get optional key use
		Use use = JWK.parseKeyUse(jsonObject);

		// Get optional intended algorithm
		Algorithm alg = JWK.parseAlgorithm(jsonObject);

		// Get optional key ID
		String kid = JWK.parseKeyID(jsonObject);

		// Check key type
		if (kty != KeyType.EC) {
			throw new ParseException("The key type \"kty\" must be EC", 0);
		}

		return new ECPublicKey(crv, x, y, use, alg, kid);
	}
}
