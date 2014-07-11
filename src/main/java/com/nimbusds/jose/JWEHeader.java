package com.nimbusds.jose;


import java.net.URL;
import java.text.ParseException;
import java.util.*;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Encryption (JWE) header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWE specification:
 *
 * <ul>
 *     <li>alg
 *     <li>enc
 *     <li>epk
 *     <li>zip
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 *     <li>apu
 *     <li>apv
 *     <li>p2s
 *     <li>p2c
 *     <li>iv
 *     <li>tag
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header:
 *
 * <pre>
 * { 
 *   "alg" : "RSA1_5",
 *   "enc" : "A128CBC-HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-11)
 */
@Immutable
public final class JWEHeader extends CommonSEHeader {


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
		p.add("enc");
		p.add("epk");
		p.add("zip");
		p.add("jku");
		p.add("jwk");
		p.add("x5u");
		p.add("x5t");
		p.add("x5c");
		p.add("kid");
		p.add("typ");
		p.add("cty");
		p.add("crit");
		p.add("apu");
		p.add("apv");
		p.add("p2s");
		p.add("p2c");
		p.add("iv");
		p.add("tag");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * Builder for constructing JSON Web Encryption (JWE) headers.
	 *
	 * <p>Example use:
	 *
	 * <pre>
	 * JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM).
	 *                    contentType("text/plain").
	 *                    customParameter("exp", new Date().getTime()).
	 *                    build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The JWE algorithm.
		 */
		private final JWEAlgorithm alg;


		/**
		 * The encryption method.
		 */
		private final EncryptionMethod enc;


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
		 * The ephemeral public key.
		 */
		private ECKey epk;


		/**
		 * The compression algorithm.
		 */
		private CompressionAlgorithm zip;


		/**
		 * The agreement PartyUInfo.
		 */
		private Base64URL apu;


		/**
		 * The agreement PartyVInfo.
		 */
		private Base64URL apv;


		/**
		 * The PBES2 salt.
		 */
		private Base64URL p2s;


		/**
		 * The PBES2 count.
		 */
		private int p2c;


		/**
		 * The initialisation vector.
		 */
		private Base64URL iv;


		/**
		 * The authentication tag.
		 */
		private Base64URL tag;


		/**
		 * Custom header parameters.
		 */
		private Map<String,Object> customParams;


		/**
		 * Creates a new JWE header builder.
		 *
		 * @param alg The JWE algorithm ({@code alg}) parameter. Must
		 *            not be "none" or {@code null}.
		 * @param enc The encryption method. Must not be {@code null}.
		 */
		public Builder(final JWEAlgorithm alg, final EncryptionMethod enc) {

			if (alg.getName().equals(Algorithm.NONE.getName())) {
				throw new IllegalArgumentException("The JWE algorithm \"alg\" cannot be \"none\"");
			}

			this.alg = alg;

			if (enc == null) {
				throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
			}

			this.enc = enc;
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
		 * Sets the Ephemeral Public Key ({@code epk}) parameter.
		 *
		 * @param epk The Ephemeral Public Key parameter, {@code null}
		 *            if not specified.
		 *
		 * @return This builder.
		 */
		public Builder ephemeralPublicKey(final ECKey epk) {

			this.epk = epk;
			return this;
		}


		/**
		 * Sets the compression algorithm ({@code zip}) parameter.
		 *
		 * @param zip The compression algorithm parameter, {@code null}
		 *            if not specified.
		 *
		 * @return This builder.
		 */
		public Builder compressionAlgorithm(final CompressionAlgorithm zip) {

			this.zip = zip;
			return this;
		}


		/**
		 * Sets the agreement PartyUInfo ({@code apu}) parameter.
		 *
		 * @param apu The agreement PartyUInfo parameter, {@code null}
		 *            if not specified.
		 *
		 * @return This builder.
		 */
		public Builder agreementPartyUInfo(final Base64URL apu) {

			this.apu = apu;
			return this;
		}


		/**
		 * Sets the agreement PartyVInfo ({@code apv}) parameter.
		 *
		 * @param apv The agreement PartyVInfo parameter, {@code null}
		 *            if not specified.
		 *
		 * @return This builder.
		 */
		public Builder agreementPartyVInfo(final Base64URL apv) {

			this.apv = apv;
			return this;
		}


		/**
		 * Sets the PBES2 salt ({@code p2s}) parameter.
		 *
		 * @param p2s The PBES2 salt parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder pbes2Salt(final Base64URL p2s) {

			this.p2s = p2s;
			return this;
		}


		/**
		 * Sets the PBES2 count ({@code p2c}) parameter.
		 *
		 * @param p2c The PBES2 count parameter, zero if not specified.
		 *            Must not be negative.
		 *
		 * @return This builder.
		 */
		public Builder pbes2Count(final int p2c) {

			if (p2c < 0)
				throw new IllegalArgumentException("The PBES2 count parameter must not be negative");

			this.p2c = p2c;
			return this;
		}


		/**
		 * Sets the initialisation vector ({@code iv}) parameter.
		 *
		 * @param iv The initialisation vector, {@code null} if not
		 *           specified.
		 *
		 * @return This builder.
		 */
		public Builder iv(final Base64URL iv) {

			this.iv = iv;
			return this;
		}


		/**
		 * Sets the authentication tag ({@code tag}) parameter.
		 *
		 * @param tag The authentication tag, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder tag(final Base64URL tag) {

			this.tag = tag;
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
		 * Builds a new JWE header.
		 *
		 * @return The JWE header.
		 */
		public JWEHeader build() {

			return new JWEHeader(
				alg, enc, typ, cty, crit,
				jku, jwk, x5u, x5t, x5c, kid,
				epk, zip, apu, apv, p2s, p2c,
				iv, tag,
				customParams, null
			);
		}
	}


	/**
	 * The encryption method ({@code enc}) parameter.
	 */
	private final EncryptionMethod enc;


	/**
	 * The ephemeral public key ({@code epk}) parameter.
	 */
	private final ECKey epk;


	/**
	 * The compression algorithm ({@code zip}) parameter.
	 */
	private final CompressionAlgorithm zip;


	/**
	 * The agreement PartyUInfo ({@code apu}) parameter.
	 */
	private final Base64URL apu;
	
	
	/**
	 * The agreement PartyVInfo ({@code apv}) parameter.
	 */
	private final Base64URL apv;


	/**
	 * The PBES2 salt ({@code p2s}) parameter.
	 */
	private final Base64URL p2s;


	/**
	 * The PBES2 count ({@code p2c}) parameter.
	 */
	private final int p2c;


	/**
	 * The initialisation vector ({@code iv}) parameter.
	 */
	private final Base64URL iv;


	/**
	 * The authentication tag ({@code tag}) parameter.
	 */
	private final Base64URL tag;


	/**
	 * Creates a new minimal JSON Web Encryption (JWE) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg The JWE algorithm parameter. Must not be "none" or
	 *            {@code null}.
	 * @param enc The encryption method parameter. Must not be 
	 *            {@code null}.
	 */
	public JWEHeader(final JWEAlgorithm alg, final EncryptionMethod enc) {

		this(
			alg, enc,
			null, null, null, null, null, null, null, null, null,
			null, null, null, null, null, 0,
			null, null,
			null, null);
	}


	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg             The JWE algorithm ({@code alg}) parameter.
	 *                        Must not be "none" or {@code null}.
	 * @param enc             The encryption method parameter. Must not be
	 *                        {@code null}.
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
	 * @param epk             The Ephemeral Public Key ({@code epk})
	 *                        parameter, {@code null} if not specified.
	 * @param zip             The compression algorithm ({@code zip})
	 *                        parameter, {@code null} if not specified.
	 * @param apu             The agreement PartyUInfo ({@code apu})
	 *                        parameter, {@code null} if not specified.
	 * @param apv             The agreement PartyVInfo ({@code apv})
	 *                        parameter, {@code null} if not specified.
	 * @param p2s             The PBES2 salt ({@code p2s}) parameter,
	 *                        {@code null} if not specified.
	 * @param p2c             The PBES2 count ({@code p2c}) parameter, zero
	 *                        if not specified. Must not be negative.
	 * @param iv              The initialisation vector ({@code iv})
	 *                        parameter, {@code null} if not specified.
	 * @param tag             The authentication tag ({@code tag})
	 *                        parameter, {@code null} if not specified.
	 * @param customParams    The custom parameters, empty map or
	 *                        {@code null} if none.
	 * @param parsedBase64URL The parsed Base64URL, {@code null} if the
	 *                        header is created from scratch.
	 */
	public JWEHeader(final Algorithm alg,
			 final EncryptionMethod enc,
			 final JOSEObjectType typ,
			 final String cty,
			 final Set<String> crit,
			 final URL jku,
			 final JWK jwk,
			 final URL x5u,
			 final Base64URL x5t,
			 final List<Base64> x5c,
			 final String kid,
			 final ECKey epk,
			 final CompressionAlgorithm zip,
			 final Base64URL apu,
			 final Base64URL apv,
			 final Base64URL p2s,
			 final int p2c,
			 final Base64URL iv,
			 final Base64URL tag,
			 final Map<String,Object> customParams,
			 final Base64URL parsedBase64URL) {

		super(alg, typ, cty, crit, jku, jwk, x5u, x5t, x5c, kid, customParams, parsedBase64URL);

		if (alg.getName().equals(Algorithm.NONE.getName())) {
			throw new IllegalArgumentException("The JWE algorithm cannot be \"none\"");
		}

		if (enc == null) {
			throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
		}

		this.enc = enc;

		this.epk = epk;
		this.zip = zip;
		this.apu = apu;
		this.apv = apv;
		this.p2s = p2s;
		this.p2c = p2c;
		this.iv = iv;
		this.tag = tag;
	}


	/**
	 * Deep copy constructor.
	 *
	 * @param jweHeader The JWE header to copy. Must not be {@code null}.
	 */
	public JWEHeader(final JWEHeader jweHeader) {

		this(
			jweHeader.getAlgorithm(),
			jweHeader.getEncryptionMethod(),
			jweHeader.getType(),
			jweHeader.getContentType(),
			jweHeader.getCriticalHeaders(),
			jweHeader.getJWKURL(),
			jweHeader.getJWK(),
			jweHeader.getX509CertURL(),
			jweHeader.getX509CertThumbprint(),
			jweHeader.getX509CertChain(),
			jweHeader.getKeyID(),
			jweHeader.getEphemeralPublicKey(),
			jweHeader.getCompressionAlgorithm(),
			jweHeader.getAgreementPartyUInfo(),
			jweHeader.getAgreementPartyVInfo(),
			jweHeader.getPBES2Salt(),
			jweHeader.getPBES2Count(),
			jweHeader.getIV(),
			jweHeader.getAuthenticationTag(),
			jweHeader.getCustomParameters(),
			jweHeader.getParsedBase64URL()
		);
	}


	/**
	 * Gets the registered parameter names for JWE headers.
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
	public JWEAlgorithm getAlgorithm() {

		return (JWEAlgorithm)super.getAlgorithm();
	}


	/**
	 * Gets the encryption method ({@code enc}) parameter.
	 *
	 * @return The encryption method parameter.
	 */
	public EncryptionMethod getEncryptionMethod() {

		return enc;
	}


	/**
	 * Gets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @return The Ephemeral Public Key parameter, {@code null} if not
	 *         specified.
	 */
	public ECKey getEphemeralPublicKey() {

		return epk;
	}


	/**
	 * Gets the compression algorithm ({@code zip}) parameter.
	 *
	 * @return The compression algorithm parameter, {@code null} if not
	 *         specified.
	 */
	public CompressionAlgorithm getCompressionAlgorithm() {

		return zip;
	}


	/**
	 * Gets the agreement PartyUInfo ({@code apu}) parameter.
	 *
	 * @return The agreement PartyUInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyUInfo() {

		return apu;
	}


	/**
	 * Gets the agreement PartyVInfo ({@code apv}) parameter.
	 *
	 * @return The agreement PartyVInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyVInfo() {

		return apv;
	}


	/**
	 * Gets the PBES2 salt ({@code p2s}) parameter.
	 *
	 * @return The PBES2 salt parameter, {@code null} if not specified.
	 */
	public Base64URL getPBES2Salt() {

		return p2s;
	}


	/**
	 * Gets the PBES2 count ({@code p2c}) parameter.
	 *
	 * @return The PBES2 count parameter, zero if not specified.
	 */
	public int getPBES2Count() {

		return p2c;
	}


	/**
	 * Gets the initialisation vector ({@code iv}) parameter.
	 *
	 * @return The initialisation vector, {@code null} if not specified.
	 */
	public Base64URL getIV() {

		return iv;
	}


	/**
	 * Gets the authentication tag ({@code tag}) parameter.
	 *
	 * @return The authentication tag, {@code null} if not specified.
	 */
	public Base64URL getAuthenticationTag() {

		return tag;
	}


	@Override
	public Set<String> getIncludedParameters() {

		Set<String> includedParameters = super.getIncludedParameters();

		if (enc != null) {
			includedParameters.add("enc");
		}

		if (epk != null) {
			includedParameters.add("epk");
		}

		if (zip != null) {
			includedParameters.add("zip");
		}

		if (apu != null) {
			includedParameters.add("apu");
		}
		
		if (apv != null) {
			includedParameters.add("apv");
		}

		if (p2s != null) {
			includedParameters.add("p2s");
		}

		if (p2c > 0) {
			includedParameters.add("p2c");
		}

		if (iv != null) {
			includedParameters.add("iv");
		}

		if (tag != null) {
			includedParameters.add("tag");
		}

		return includedParameters;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		if (enc != null) {
			o.put("enc", enc.toString());
		}

		if (epk != null) {
			o.put("epk", epk.toJSONObject());
		}

		if (zip != null) {
			o.put("zip", zip.toString());
		}

		if (apu != null) {
			o.put("apu", apu.toString());
		}
		
		if (apv != null) {
			o.put("apv", apv.toString());
		}

		if (p2s != null) {
			o.put("p2s", p2s.toString());
		}

		if (p2c > 0) {
			o.put("p2c", p2c);
		}

		if (iv != null) {
			o.put("iv", iv.toString());
		}

		if (tag != null) {
			o.put("tag", tag.toString());
		}

		return o;
	}


	/**
	 * Parses an encryption method ({@code enc}) parameter from the 
	 * specified JWE header JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The encryption method.
	 *
	 * @throws ParseException If the {@code enc} parameter couldn't be 
	 *                        parsed.
	 */
	private static EncryptionMethod parseEncryptionMethod(final JSONObject json)
		throws ParseException {

		return EncryptionMethod.parse(JSONObjectUtils.getString(json, "enc"));
	}


	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject jsonObject)
		throws ParseException {

		return parse(jsonObject, null);
	}


	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param jsonObject      The JSON object to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject jsonObject,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (! (alg instanceof JWEAlgorithm)) {
			throw new ParseException("The algorithm \"alg\" header parameter must be for encryption", 0);
		}

		// Get the "enc" parameter
		EncryptionMethod enc = parseEncryptionMethod(jsonObject);

		JOSEObjectType typ = null;
		String cty = null;
		Set<String> crit = null;
		URL jku = null;
		JWK jwk = null;
		URL x5u = null;
		Base64URL x5t = null;
		List<Base64> x5c = null;
		String kid = null;
		ECKey epk = null;
		CompressionAlgorithm zip = null;
		Base64URL apu = null;
		Base64URL apv = null;
		Base64URL p2s = null;
		int p2c = 0;
		Base64URL iv = null;
		Base64URL tag = null;
		Map<String,Object> customParams = new HashMap<String,Object>();

		// Parse optional + custom parameters
		for(final String name: jsonObject.keySet()) {
			if (name.equals("alg")) {
				// skip
			} else if (name.equals("enc")) {
				// skip
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
			} else if (name.equals("epk")) {
				epk = ECKey.parse(JSONObjectUtils.getJSONObject(jsonObject, name));
			} else if (name.equals("zip")) {
				zip = new CompressionAlgorithm(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("apu")) {
				apu = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("apv")) {
				apv = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("p2s")) {
				p2s = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("p2c")) {
				p2c = JSONObjectUtils.getInt(jsonObject, name);
			} else if (name.equals("iv")) {
				iv = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("tag")) {
				tag = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else {
				customParams.put(name, jsonObject.get(name));
			}
		}

		return new JWEHeader(
			alg, enc, typ, cty, crit, jku, jwk, x5u, x5t, x5c, kid,
			epk, zip, apu, apv, p2s, p2c,
			iv, tag,
			customParams, parsedBase64URL
		);
	}


	/**
	 * Parses a JWE header from the specified JSON object string.
	 *
	 * @param jsonString The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String jsonString)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), null);
	}


	/**
	 * Parses a JWE header from the specified JSON object string.
	 *
	 * @param jsonString      The JSON string to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String jsonString,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
	}


	/**
	 * Parses a JWE header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent
	 *                        a valid JWE header.
	 */
	public static JWEHeader parse(final Base64URL base64URL)
		throws ParseException {

		return parse(base64URL.decodeToString(), base64URL);
	}
}
