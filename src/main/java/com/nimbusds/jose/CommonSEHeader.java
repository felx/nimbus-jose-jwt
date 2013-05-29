package com.nimbusds.jose;


import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Common class for JWS and JWE headers.
 *
 * <p>Supports all reserved header parameters shared by the JWS and JWE
 * specifications:
 *
 * <ul>
 *     <li>alg
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-29)
 */
abstract class CommonSEHeader extends Header implements ReadOnlyCommonSEHeader {


	/**
	 * JWK Set URL, {@code null} if not specified.
	 */
	private URL jku;


	/**
	 * JWK, {@code null} if not specified.
	 */
	private JWK jwk;


	/**
	 * X.509 certificate URL, {@code null} if not specified.
	 */
	private URL x5u;


	/**
	 * X.509 certificate thumbprint, {@code null} if not specified.
	 */
	private Base64URL x5t;


	/**
	 * The X.509 certificate chain corresponding to the key used to sign or 
	 * encrypt the JWS/JWE object, {@code null} if not specified.
	 */
	private Base64[] x5c;


	/**
	 * Key ID, {@code null} if not specified.
	 */
	private String kid;


	/**
	 * Creates a new common JWS and JWE header with the specified algorithm 
	 * ({@code alg}) parameter.
	 *
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	protected CommonSEHeader(final Algorithm alg) {

		super(alg);
	}


	@Override
	public URL getJWKURL() {

		return jku;
	}


	/**
	 * Sets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
	 *
	 * @param jku The JSON Web Key (JWK) Set URL parameter, {@code null} if 
	 *            not specified.
	 */
	public void setJWKURL(final URL jku) {

		this.jku = jku;
	}


	@Override
	public JWK getJWK() {

		return jwk;
	}


	/**
	 * Sets the JSON Web Key (JWK) ({@code jwk}) parameter.
	 *
	 * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter, 
	 *            {@code null} if not specified.
	 */
	public void setJWK(final JWK jwk) {

		this.jwk = jwk;
	}


	@Override
	public URL getX509CertURL() {

		return x5u;
	}


	/**
	 * Sets the X.509 certificate URL ({@code x5u}) parameter.
	 *
	 * @param x5u The X.509 certificate URL parameter, {@code null} if not 
	 *            specified.
	 */
	public void setX509CertURL(final URL x5u) {

		this.x5u = x5u;
	}


	@Override
	public Base64URL getX509CertThumbprint() {

		return x5t;
	}


	/**
	 * Sets the X.509 certificate thumbprint ({@code x5t}) parameter.
	 *
	 * @param x5t The X.509 certificate thumbprint parameter, {@code null}  
	 *            if not specified.
	 */
	public void setX509CertThumbprint(final Base64URL x5t) {

		this.x5t = x5t;
	}


	@Override
	public Base64[] getX509CertChain() {

		return x5c;
	}


	/**
	 * Sets the X.509 certificate chain parameter ({@code x5c}) 
	 * corresponding to the key used to sign or encrypt the JWS/JWE object.
	 *
	 * @param x5c The X.509 certificate chain parameter, {@code null} if not
	 *            specified.
	 */
	public void setX509CertChain(final Base64[] x5c) {

		this.x5c = x5c;
	}


	@Override
	public String getKeyID() {

		return kid;
	}


	/**
	 * Sets the key ID ({@code kid}) parameter.
	 *
	 * @param kid The key ID parameter, {@code null} if not specified.
	 */
	public void setKeyID(final String kid) {

		this.kid = kid;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		if (jku != null) {
			o.put("jku", jku.toString());
		}

		if (jwk != null) {
			o.put("jwk", jwk.toJSONObject());
		}

		if (x5u != null) {
			o.put("x5u", x5u.toString());
		}

		if (x5t != null) {
			o.put("x5t", x5t.toString());
		}

		if (x5c != null) {
			o.put("x5c", Arrays.asList(x5c));
		}

		if (kid != null) {
			o.put("kid", kid);
		}

		return o;
	}


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
	protected static Base64[] parseX509CertChain(final JSONArray jsonArray)
		throws ParseException {

		Base64[] chain = new Base64[jsonArray.size()];

		for (int i=0; i < jsonArray.size(); i++) {

			Object item = jsonArray.get(i);

			if (item == null) {
				throw new ParseException("The X.509 certificate at position " + i + " must not be null", 0);
			}

			if  (! (item instanceof String)) {
				throw new ParseException("The X.509 certificate must be encoded as a Base64 string", 0);
			}

			chain[i] = new Base64((String)item);
		}

		return chain;
	}
}
