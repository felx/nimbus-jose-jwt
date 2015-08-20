package com.nimbusds.jose.proc;


import java.text.ParseException;

import com.nimbusds.jose.*;


/**
 * Interface for parsing and processing {@link com.nimbusds.jose.PlainObject
 * unsecured} (plain), {@link com.nimbusds.jose.JWSObject JWS} and
 * {@link com.nimbusds.jose.JWEObject JWE} objects.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-20
 */
public interface JOSEProcessor<C extends SecurityContext> {


	/**
	 * Parses and processes the specified JOSE object (unsecured, JWS or
	 * JWE).
	 *
	 * @param compactEncodedJOSE The JOSE object, compact-encoded to a
	 *                           URL-safe string. Must not be {@code null}.
	 * @param context            Optional context of the JOSE object,
	 *                           {@code null} if not required.
	 *
	 * @return The payload on success.
	 *
	 * @throws ParseException   If the string couldn't be parsed to a valid
	 *                          JOSE object.
	 * @throws BadJOSEException If the JOSE object is rejected.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	Payload process(final String compactEncodedJOSE, final C context)
		throws ParseException, BadJOSEException, JOSEException;


	/**
	 * Processes the specified JOSE object (unsecured, JWS or JWE).
	 *
	 * @param joseObject The JOSE object. Must not be {@code null}.
	 * @param context    Optional context of the JOSE object, {@code null}
	 *                   if not required.
	 *
	 * @return The payload on success.
	 *
	 * @throws BadJOSEException If the JOSE object is rejected.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	Payload process(final JOSEObject joseObject, final C context)
		throws BadJOSEException, JOSEException;


	/**
	 * Processes the specified unsecured (plain) JOSE object, typically by
	 * checking its context.
	 *
	 * @param plainObject The unsecured (plain) JOSE object. Not
	 *                    {@code null}.
	 * @param context     Optional context of the unsecured JOSE object,
	 *                    {@code null} if not required.
	 *
	 * @return The payload on success.
	 *
	 * @throws BadJOSEException If the unsecured (plain) JOSE object is
	 *                          rejected.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	Payload process(final PlainObject plainObject, final C context)
		throws BadJOSEException, JOSEException;


	/**
	 * Processes the specified JWS object by verifying its signature. The
	 * key candidate(s) are selected by examining the JWS header and / or
	 * the message context.
	 *
	 * @param jwsObject The JWS object. Not {@code null}.
	 * @param context   Optional context of the JWS object, {@code null} if
	 *                  not required.
	 *
	 * @return The payload on success.
	 *
	 * @throws BadJOSEException If the JWS object is rejected, typically
	 *                          due to a bad signature.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	Payload process(final JWSObject jwsObject, final C context)
		throws BadJOSEException, JOSEException;


	/**
	 * Processes the specified JWE object by decrypting it. The key
	 * candidate(s) are selected by examining the JWS header and / or the
	 * message context.
	 *
	 * @param jweObject The JWE object. Not {@code null}.
	 * @param context   Optional context of the JWE object, {@code null} if
	 *                  not required.
	 *
	 * @return The payload on success.
	 *
	 * @throws BadJOSEException If the JWE object is rejected, typically
	 *                          due to failed decryption.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	Payload process(final JWEObject jweObject, final C context)
		throws BadJOSEException, JOSEException;
}

