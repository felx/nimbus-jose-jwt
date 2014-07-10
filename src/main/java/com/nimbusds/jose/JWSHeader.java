package com.nimbusds.jose;


import java.net.URL;
import java.text.ParseException;
import java.util.*;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Signature (JWS) header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWS specification:
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
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header of a JSON Web Signature (JWS) object using the 
 * {@link JWSAlgorithm#HS256 HMAC SHA-256 algorithm}:
 *
 * <pre>
 * {
 *   "alg" : "HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-09)
 */
@Immutable
public final class JWSHeader extends CommonSEHeader {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<String>();

		p.add("alg");
		p.add("jku");
		p.add("jwk");
		p.add("x5u");
		p.add("x5t");
		p.add("x5c");
		p.add("kid");
		p.add("typ");
		p.add("cty");
		p.add("crit");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * Builder for constructing JSON Web Signature (JWS) headers.
	 *
	 * <p>Example use:
	 *
	 * <pre>
	 * JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
	 *                    contentType("text/plain").
	 *                    customParameter("exp", new Date().getTime()).
	 *                    build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The JWS algorithm.
		 */
		private final JWSAlgorithm alg;


		/**
		 * The JOSE object type.
		 */
		private JOSEObjectType typ;


		/**
		 * The content type.
		 */
		private String cty;


		/**
		 * The critical headers.
		 */
		private Set<String> crit;


		/**
		 * JWK Set URL.
		 */
		private URL jku;


		/**
		 * JWK.
		 */
		private JWK jwk;


		/**
		 * X.509 certificate URL.
		 */
		private URL x5u;


		/**
		 * X.509 certificate thumbprint.
		 */
		private Base64URL x5t;


		/**
		 * The X.509 certificate chain corresponding to the key used to
		 * sign the JWS object.
		 */
		private List<Base64> x5c;


		/**
		 * Key ID.
		 */
		private String kid;


		/**
		 * Custom header parameters.
		 */
		private Map<String,Object> customParams;


		/**
		 * Creates a new JWS header builder.
		 *
		 * @param alg The JWS algorithm ({@code alg}) parameter. Must
		 *            not be "none" or {@code null}.
		 */
		public Builder(final JWSAlgorithm alg) {

			if (alg.getName().equals(Algorithm.NONE.getName())) {
				throw new IllegalArgumentException("The JWS algorithm \"alg\" cannot be \"none\"");
			}

			this.alg = alg;
		}


		/**
		 * Sets the type ({@code typ}) parameter.
		 *
		 * @param typ The type parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder type(final JOSEObjectType typ) {

			this.typ = typ;
			return this;
		}


		/**
		 * Sets the content type ({@code cty}) parameter.
		 *
		 * @param cty The content type parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder contentType(final String cty) {

			this.cty = cty;
			return this;
		}


		/**
		 * Sets the critical headers ({@code crit}) parameter.
		 *
		 * @param crit The names of the critical header parameters,
		 *             empty set or {@code null} if none.
		 *
		 * @return This builder.
		 */
		public Builder criticalHeaders(final Set<String> crit) {

			this.crit = crit;
			return this;
		}


		/**
		 * Sets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
		 *
		 * @param jku The JSON Web Key (JWK) Set URL parameter,
		 *            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder jwkURL(final URL jku) {

			this.jku = jku;
			return this;
		}


		/**
		 * Sets the JSON Web Key (JWK) ({@code jwk}) parameter.
		 *
		 * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter,
		 *            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder jwk(final JWK jwk) {

			this.jwk = jwk;
			return this;
		}


		/**
		 * Sets the X.509 certificate URL ({@code x5u}) parameter.
		 *
		 * @param x5u The X.509 certificate URL parameter, {@code null}
		 *            if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertURL(final URL x5u) {

			this.x5u = x5u;
			return this;
		}


		/**
		 * Sets the X.509 certificate thumbprint ({@code x5t})
		 * parameter.
		 *
		 * @param x5t The X.509 certificate thumbprint parameter,
		 *            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertThumbprint(final Base64URL x5t) {

			this.x5t = x5t;
			return this;
		}


		/**
		 * Sets the X.509 certificate chain parameter ({@code x5c})
		 * corresponding to the key used to sign the JWS object.
		 *
		 * @param x5c The X.509 certificate chain parameter,
		 *            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertChain(final List<Base64> x5c) {

			this.x5c = x5c;
			return this;
		}


		/**
		 * Sets the key ID ({@code kid}) parameter.
		 *
		 * @param kid The key ID parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String kid) {

			this.kid = kid;
			return this;
		}


		/**
		 * Sets a custom (non-registered) parameter.
		 *
		 * @param name  The name of the custom parameter. Must not
		 *              match a registered parameter name and must not
		 *              be {@code null}.
		 * @param value The value of the custom parameter, should map
		 *              to a valid JSON entity, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 *
		 * @throws IllegalArgumentException If the specified parameter
		 *                                  name matches a registered
		 *                                  parameter name.
		 */
		public Builder customParameter(final String name, final Object value) {

			if (getRegisteredParameterNames().contains(name)) {
				throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
			}

			if (customParams == null) {
				customParams = new HashMap<String,Object>();
			}

			customParams.put(name, value);

			return this;
		}


		/**
		 * Sets the custom (non-registered) parameters. The values must
		 * be serialisable to a JSON entity, otherwise will be ignored.
		 *
		 * @param customParameters The custom parameters, empty map or
		 *                         {@code null} if none.
		 *
		 * @return This builder.
		 */
		public Builder customParameters(final Map<String,Object> customParameters) {

			this.customParams = customParameters;
			return this;
		}


		/**
		 * Builds a new JWS header.
		 *
		 * @return The JWS header.
		 */
		public JWSHeader build() {

			return new JWSHeader(
				alg, typ, cty, crit,
				jku, jwk, x5u, x5t, x5c, kid,
				customParams, null);
		}
	}


	/**
	 * Creates a new minimal JSON Web Signature (JWS) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg The JWS algorithm ({@code alg}) parameter. Must not be
	 *            "none" or {@code null}.
	 */
	public JWSHeader(final JWSAlgorithm alg) {

		this(alg, null, null, null, null, null, null, null, null, null, null, null);
	}


	/**
	 * Creates a new JSON Web Signature (JWS) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg             The JWS algorithm ({@code alg}) parameter.
	 *                        Must not be "none" or {@code null}.
	 * @param typ             The type ({@code typ}) parameter,
	 *                        {@code null} if not specified.
	 * @param cty             The content type ({@code cty}) parameter,
	 *                        {@code null} if not specified.
	 * @param crit            The names of the critical header
	 *                        ({@code crit}) parameters, empty set or
	 *                        {@code null} if none.
	 * @param jku             The JSON Web Key (JWK) Set URL ({@code jku})
	 *                        parameter, {@code null} if not specified.
	 * @param jwk             The X.509 certificate URL ({@code jwk})
	 *                        parameter, {@code null} if not specified.
	 * @param x5u             The X.509 certificate URL parameter
	 *                        ({@code x5u}), {@code null} if not specified.
	 * @param x5t             The X.509 certificate thumbprint
	 *                        ({@code x5t}) parameter, {@code null} if not
	 *                        specified.
	 * @param x5c             The X.509 certificate chain ({@code x5c})
	 *                        parameter, {@code null} if not specified.
	 * @param kid             The key ID ({@code kid}) parameter,
	 *                        {@code null} if not specified.
	 * @param customParams    The custom parameters, empty map or
	 *                        {@code null} if none.
	 * @param parsedBase64URL The parsed Base64URL, {@code null} if the
	 *                        header is created from scratch.
	 */
	public JWSHeader(final JWSAlgorithm alg,
			 final JOSEObjectType typ,
			 final String cty,
			 final Set<String> crit,
			 final URL jku,
			 final JWK jwk,
			 final URL x5u,
			 final Base64URL x5t,
			 final List<Base64> x5c,
			 final String kid,
			 final Map<String,Object> customParams,
			 final Base64URL parsedBase64URL) {

		super(alg, typ, cty, crit, jku, jwk, x5u, x5t, x5c, kid, customParams, parsedBase64URL);

		if (alg.getName().equals(Algorithm.NONE.getName())) {
			throw new IllegalArgumentException("The JWS algorithm \"alg\" cannot be \"none\"");
		}
	}


	/**
	 * Gets the registered parameter names for JWS headers.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	@Override
	public JWSAlgorithm getAlgorithm() {

		return (JWSAlgorithm)super.getAlgorithm();
	}


	/**
	 * Parses a JWS header from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final JSONObject jsonObject)
		throws ParseException {

		return parse(jsonObject, null);
	}


	/**
	 * Parses a JWS header from the specified JSON object.
	 *
	 * @param jsonObject      The JSON object to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final JSONObject jsonObject,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (! (alg instanceof JWSAlgorithm)) {
			throw new ParseException("The algorithm \"alg\" header parameter must be for signatures", 0);
		}

		JOSEObjectType typ = null;
		String cty = null;
		Set<String> crit = null;
		URL jku = null;
		JWK jwk = null;
		URL x5u = null;
		Base64URL x5t = null;
		List<Base64> x5c = null;
		String kid = null;
		Map<String,Object> customParams = new HashMap<String,Object>();

		// Parse optional + custom parameters
		for (final String name: jsonObject.keySet()) {

			if (name.equals("alg")) {
				continue; // Skip
			} else if (name.equals("typ")) {
				typ = new JOSEObjectType(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("cty")) {
				cty = JSONObjectUtils.getString(jsonObject, name);
			} else if (name.equals("crit")) {
				crit = new HashSet<String>(JSONObjectUtils.getStringList(jsonObject, name));
			} else if (name.equals("jku")) {
				jku = JSONObjectUtils.getURL(jsonObject, name);
			} else if (name.equals("jwk")) {
				jwk = JWK.parse(JSONObjectUtils.getJSONObject(jsonObject, name));
			} else if (name.equals("x5u")) {
				x5u = JSONObjectUtils.getURL(jsonObject, name);
			} else if (name.equals("x5t")) {
				x5t = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("x5c")) {
				x5c = X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(jsonObject, name));
			} else if (name.equals("kid")) {
				kid = JSONObjectUtils.getString(jsonObject, name);
			} else {
				customParams.put(name, jsonObject.get(name));
			}
		}

		return new JWSHeader(
			(JWSAlgorithm)alg, typ, cty, crit,
			jku, jwk, x5u, x5t, x5c, kid,
			customParams, parsedBase64URL);
	}


	/**
	 * Parses a JWS header from the specified JSON object string.
	 *
	 * @param jsonString The JSON string to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final String jsonString)
		throws ParseException {

		return parse(jsonString, null);
	}


	/**
	 * Parses a JWS header from the specified JSON object string.
	 *
	 * @param jsonString      The JSON string to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final String jsonString,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
	}


	/**
	 * Parses a JWS header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent
	 *                        a valid JWS header.
	 */
	public static JWSHeader parse(final Base64URL base64URL)
		throws ParseException {

		return parse(base64URL.decodeToString(), base64URL);
	}
}
