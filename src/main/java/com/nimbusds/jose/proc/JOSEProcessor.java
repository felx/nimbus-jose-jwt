package com.nimbusds.jose.proc;


import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.PlainObject;


/**
 * Interface for parsing and processing {@link com.nimbusds.jose.PlainObject
 * unsecured} (plain), {@link com.nimbusds.jose.JWSObject JWS} and
 * {@link com.nimbusds.jose.JWEObject JWE} objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-10)
 */
public interface JOSEProcessor<T, C extends SecurityContext> {


	/**
	 * Parses and processes the specified JOSE object (unsecured, JWS or
	 * JWE).
	 *
	 * @param compactEncodedJOSE The JOSE object, compact-encoded to a
	 *                           URL-safe string. Must not be {@code null}.
	 * @param context            Optional context of the JOSE object,
	 *                           {@code null} if not required.
	 *
	 * @return An application-specific object (the payload) on success, or
	 *         {@code null} if no return value is necessary.
	 *
	 * @throws ParseException   If the string couldn't be parsed to a valid
	 *                          JOSE object.
	 * @throws BadJOSEException If the unsecured (plain) JOSE object is
	 *                          rejected.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	T process(final String compactEncodedJOSE, final C context)
		throws ParseException, BadJOSEException, JOSEException;


	/**
	 * Processes the specified unsecured (plain) JOSE object by checking
	 * its context.
	 *
	 * @param plainObject The unsecured (plain) JOSE object. Not
	 *                    {@code null}.
	 * @param context     Optional context of the unsecured JOSE object,
	 *                    {@code null} if not required.
	 *
	 * @return An application-specific object (the payload) on success, or
	 *         {@code null} if no return value is necessary.
	 *
	 * @throws BadJOSEException If the unsecured (plain) JOSE object is
	 *                          rejected.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	T process(final PlainObject plainObject, final C context)
		throws BadJOSEException, JOSEException;


	/**
	 * Processes the specified JWS object by verifying its signature and
	 * checking its context.
	 *
	 * @param jwsObject The JWS object. Not {@code null}.
	 * @param context   Optional context of the JWS object, {@code null} if
	 *                  not required.
	 *
	 * @return An application-specific object (the payload) on success, or
	 *         {@code null} if no return value is necessary.
	 *
	 * @throws BadJOSEException If the JWS object is rejected, typically due
	 *                          to a bad signature.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	T process(final JWSObject jwsObject, final C context)
		throws BadJOSEException, JOSEException;


	/**
	 * Processes the specified JWE object by decrypting it and checking its
	 * context.
	 *
	 * @param jweObject The JWE object. Not {@code null}.
	 * @param context   Optional context of the JWE object, {@code null} if
	 *                  not required.
	 *
	 * @return An application-specific object (the payload) on success, or
	 *         {@code null} if no return value is necessary.
	 *
	 * @throws BadJOSEException If the JWE object is rejected, typically due
	 *                          to failed decryption.
	 * @throws JOSEException    If an internal processing exception is
	 *                          encountered.
	 */
	T process(final JWEObject jweObject, final C context)
		throws BadJOSEException, JOSEException;
}

