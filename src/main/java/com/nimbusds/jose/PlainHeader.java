package com.nimbusds.jose;


import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Plaintext JOSE header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the plain specification:
 *
 * <ul>
 *     <li>alg (set to {@link Algorithm#NONE "none"}).
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the registered ones.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "alg" : "none"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-10-07)
 */
public class PlainHeader extends Header implements ReadOnlyPlainHeader {


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
		p.add("typ");
		p.add("cty");
		p.add("crit");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * Creates a new plain header with algorithm 
	 * {@link Algorithm#NONE none}.
	 */
	public PlainHeader() {

		super(Algorithm.NONE);
	}


	/**
	 * Gets the registered parameter names for plain headers.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	@Override
	public Algorithm getAlgorithm() {

		return alg;
	}


	/**
	 * @throws IllegalArgumentException If the specified parameter name
	 *                                  matches a registered parameter
	 *                                  name.
	 */
	@Override
	public void setCustomParameter(final String name, final Object value) {

		if (getRegisteredParameterNames().contains(name)) {
			throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
		}

		super.setCustomParameter(name, value);
	}


	@Override
	public Set<String> getIncludedParameters() {

		Set<String> includedParameters = 
			new HashSet<String>(getCustomParameters().keySet());

		includedParameters.add("alg");

		if (getType() != null) {
			includedParameters.add("typ");
		}

		if (getContentType() != null) {
			includedParameters.add("cty");
		}

		if (getCriticalHeaders() != null && ! getCriticalHeaders().isEmpty()) {
			includedParameters.add("crit");
		}

		return includedParameters;
	}


	/**
	 * Parses a plain header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid plain header.
	 */
	public static PlainHeader parse(final JSONObject json)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);

		if (alg != Algorithm.NONE) {
			throw new ParseException("The algorithm \"alg\" header parameter must be \"none\"", 0);
		}


		// Create a minimal header, type may be set later
		PlainHeader h = new PlainHeader();


		// Parse optional + custom parameters
		for(final String name: json.keySet()) {

			if (name.equals("alg")) {
				continue; // skip
			} else if (name.equals("typ")) {
				h.setType(new JOSEObjectType(JSONObjectUtils.getString(json, name)));
			} else if (name.equals("cty")) {
				h.setContentType(JSONObjectUtils.getString(json, name));
			} else if (name.equals("crit")) {
				h.setCriticalHeaders(new HashSet<String>(JSONObjectUtils.getStringList(json, name)));
			} else {
				h.setCustomParameter(name, json.get(name));
			}
		}

		return h;
	}


	/**
	 * Parses a plain header from the specified JSON string.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON string doesn't 
	 *                        represent a valid plain header.
	 */
	public static PlainHeader parse(final String s)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(s);

		return parse(jsonObject);
	}


	/**
	 * Parses a plain header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent
	 *                        a valid plain header.
	 */
	public static PlainHeader parse(final Base64URL base64URL)
		throws ParseException {

		if (base64URL == null) {
			throw new ParseException("The Base64URL must not be null", 0);
		}

		PlainHeader header = parse(base64URL.decodeToString());
		header.setParsedBase64URL(base64URL);
		return header;
	}
}
