package com.nimbusds.jose;


import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Encryption (JWE) header.
 *
 * <p>Supports all {@link #getReservedParameterNames reserved header parameters}
 * of the JWE specification:
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
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
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
 * @version $version$ (2013-08-20)
 */
public class JWEHeader extends CommonSEHeader implements ReadOnlyJWEHeader {


	/**
	 * The reserved parameter names.
	 */
	private static final Set<String> RESERVED_PARAMETER_NAMES;


	/**
	 * Initialises the reserved parameter name set.
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

		RESERVED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The encryption method ({@code enc}) parameter.
	 */
	private EncryptionMethod enc;


	/**
	 * The ephemeral public key ({@code epk}) parameter.
	 */
	private ECKey epk;


	/**
	 * The compression algorithm ({@code zip}) parameter.
	 */
	private CompressionAlgorithm zip;


	/**
	 * The agreement PartyUInfo ({@code apu}) parameter.
	 */
	private Base64URL apu;
	
	
	/**
	 * The agreement PartyVInfo ({@code apv}) parameter.
	 */
	private Base64URL apv;


	/**
	 * The PBES2 salt ({@code p2s}) parameter.
	 */
	private Base64URL p2s;


	/**
	 * The PBES2 count ({@code p2c}) parameter.
	 */
	private int p2c;


	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * @param alg The JWE algorithm parameter. Must not be {@code null}.
	 * @param enc The encryption method parameter. Must not be 
	 *            {@code null}.
	 */
	public JWEHeader(final JWEAlgorithm alg, final EncryptionMethod enc) {

		super(alg);

		if (enc == null) {
			throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
		}

		this.enc = enc;
	}


	/**
	 * Gets the reserved parameter names for JWE headers.
	 *
	 * @return The reserved parameter names, as an unmodifiable set.
	 */
	public static Set<String> getReservedParameterNames() {

		return RESERVED_PARAMETER_NAMES;
	}


	@Override
	public JWEAlgorithm getAlgorithm() {

		return (JWEAlgorithm)alg;
	}


	@Override
	public EncryptionMethod getEncryptionMethod() {

		return enc;
	}


	@Override
	public ECKey getEphemeralPublicKey() {

		return epk;
	}


	/**
	 * Sets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @param epk The Ephemeral Public Key parameter, {@code null} if not 
	 *            specified.
	 */
	public void setEphemeralPublicKey(final ECKey epk) {

		this.epk = epk;
	}


	@Override
	public CompressionAlgorithm getCompressionAlgorithm() {

		return zip;
	}


	/**
	 * Sets the compression algorithm ({@code zip}) parameter.
	 *
	 * @param zip The compression algorithm parameter, {@code null} if not 
	 *            specified.
	 */
	public void setCompressionAlgorithm(final CompressionAlgorithm zip) {

		this.zip = zip;
	}


	@Override
	public Base64URL getAgreementPartyUInfo() {

		return apu;
	}


	/**
	 * Sets the agreement PartyUInfo ({@code apu}) parameter.
	 *
	 * @param apu The agreement PartyUInfo parameter, {@code null} if not
	 *            specified.
	 */
	public void setAgreementPartyUInfo(final Base64URL apu) {

		this.apu = apu;
	}
	
	
	@Override
	public Base64URL getAgreementPartyVInfo() {

		return apv;
	}


	/**
	 * Sets the agreement PartyVInfo ({@code apv}) parameter.
	 *
	 * @param apv The agreement PartyVInfo parameter, {@code null} if not
	 *            specified.
	 */
	public void setAgreementPartyVInfo(final Base64URL apv) {

		this.apv = apv;
	}


	@Override
	public Base64URL getPBES2Salt() {

		return p2s;
	}


	/**
	 * Sets the PBES2 salt ({@code p2s}) parameter.
	 *
	 * @param p2s The PBES2 salt parameter, {@code null} if not specified.
	 */
	public void setPBES2Salt(final Base64URL p2s) {

		this.p2s = p2s;
	}


	@Override
	public int getPBES2Count() {

		return p2c;
	}


	/**
	 * Sets the PBES2 count ({@code p2c}) parameter.
	 *
	 * @param p2c The PBES2 count parameter, zero if not specified. Must
	 *            not be negative.
	 */
	public void setPBES2Count(final int p2c) {

		if (p2c < 0)
			throw new IllegalArgumentException("The PBES2 count parameter must not be negative");

		this.p2c = p2c;
	}


	/**
	 * @throws IllegalArgumentException If the specified parameter name
	 *                                  matches a reserved parameter name.
	 */
	@Override
	public void setCustomParameter(final String name, final Object value) {

		if (getReservedParameterNames().contains(name)) {
			throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a reserved name");
		}

		super.setCustomParameter(name, value);
	}


	@Override
	public Set<String> getIncludedParameters() {

		Set<String> includedParameters = 
			new HashSet<String>(getCustomParameters().keySet());

		includedParameters.add("alg");
		includedParameters.add("enc");

		if (getEphemeralPublicKey() != null) {
			includedParameters.add("epk");
		}

		if (getCompressionAlgorithm() != null) {
			includedParameters.add("zip");
		}

		if (getType() != null) {
			includedParameters.add("typ");
		}

		if (getContentType() != null) {
			includedParameters.add("cty");
		}

		if (getCriticalHeaders() != null && ! getCriticalHeaders().isEmpty()) {
			includedParameters.add("crit");
		}

		if (getJWKURL() != null) {
			includedParameters.add("jku");
		}

		if (getJWK() != null) {
			includedParameters.add("jwk");
		}

		if (getX509CertURL() != null) {
			includedParameters.add("x5u");
		}

		if (getX509CertThumbprint() != null) {
			includedParameters.add("x5t");
		}

		if (getX509CertChain() != null) {
			includedParameters.add("x5c");
		}

		if (getKeyID() != null) {
			includedParameters.add("kid");
		}

		if (getAgreementPartyUInfo() != null) {
			includedParameters.add("apu");
		}
		
		if (getAgreementPartyVInfo() != null) {
			includedParameters.add("apv");
		}

		if (getPBES2Salt() != null) {
			includedParameters.add("p2s");
		}

		if (getPBES2Count() > 0) {
			includedParameters.add("p2c");
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
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject json)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);

		if (! (alg instanceof JWEAlgorithm)) {
			throw new ParseException("The algorithm \"alg\" header parameter must be for encryption", 0);
		}

		// Get the "enc" parameter
		EncryptionMethod enc = parseEncryptionMethod(json);

		// Create a minimal header
		JWEHeader h = new JWEHeader((JWEAlgorithm)alg, enc);

		// Parse optional + custom parameters
		for(final String name: json.keySet()) {

			if (name.equals("alg")) {
				continue; // skip
			} else if (name.equals("enc")) {
				continue; // skip
			} else if (name.equals("epk")) {
				h.setEphemeralPublicKey(ECKey.parse(JSONObjectUtils.getJSONObject(json, name)));
			} else if (name.equals("zip")) {
				h.setCompressionAlgorithm(new CompressionAlgorithm(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("typ")) {
				h.setType(new JOSEObjectType(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("cty")) {
				h.setContentType(JSONObjectUtils.getString(json, name));
			} else if (name.equals("crit")) {
				h.setCriticalHeaders(new HashSet<String>(JSONObjectUtils.getStringList(json, name)));
			} else if (name.equals("jku")) {
				h.setJWKURL(JSONObjectUtils.getURL(json, name));
			} else if (name.equals("jwk")) {
				h.setJWK(JWK.parse(JSONObjectUtils.getJSONObject(json, name)));
			} else if (name.equals("x5u")) {
				h.setX509CertURL(JSONObjectUtils.getURL(json, name));
			} else if (name.equals("x5t")) {
				h.setX509CertThumbprint(new Base64URL(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("x5c")) {
				h.setX509CertChain(X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(json, name)));
			} else if (name.equals("kid")) {
				h.setKeyID(JSONObjectUtils.getString(json, name));
			} else if (name.equals("apu")) {
				h.setAgreementPartyUInfo(new Base64URL(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("apv")) {
				h.setAgreementPartyVInfo(new Base64URL(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("p2s")) {
				h.setPBES2Salt(new Base64URL(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("p2c")) {
				h.setPBES2Count(JSONObjectUtils.getInt(json, name));
			} else {
				h.setCustomParameter(name, json.get(name));
			}
		}

		return h;
	}


	/**
	 * Parses a JWE header from the specified JSON object string.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String s)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(s);

		return parse(jsonObject);
	}


	/**
	 * Parses a JWE header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent a 
	 *                        valid JWE header.
	 */
	public static JWEHeader parse(final Base64URL base64URL)
		throws ParseException {

		JWEHeader header = parse(base64URL.decodeToString());
		header.setParsedBase64URL(base64URL);
		return header;
	}
}
