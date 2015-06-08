package com.nimbusds.jose.handler;


import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.PlainObject;


/**
 * Handler of parsed {@link com.nimbusds.jose.JOSEObject}s. Invoked by the
 * {@link com.nimbusds.jose.JOSEObject#parse(String,JOSEObjectHandler,Context)}
 * method to indicate the exact type of the parsed object - {@link PlainObject
 * plain}, {@link JWSObject signed} or {@link JWEObject encrypted object}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-22)
 */
public interface JOSEObjectHandler<T, C extends Context> {


	/**
	 * Invoked when the parsed JOSE object is unsecured (plain).
	 *
	 * @param plainObject The parsed unsecured JOSE object. Not
	 *                    {@code null}.
	 * @param context     Optional context of the unsecured JOSE object,
	 *                    {@code null} if not required.
	 *
	 * @return Any object to be used after inspecting the unsecured JOSE
	 *         object, or {@code null} if no return value is necessary.
	 */
	T onPlainObject(final PlainObject plainObject, final C context);


	/**
	 * Invoked when the the parsed JOSE object is a JWS object.
	 *
	 * @param jwsObject The parsed JWS object. Not {@code null}.
	 * @param context   Optional context of the JWS object, {@code null} if
	 *                  not required.
	 *
	 * @return Any object to be used after inspecting the JWS object, or
	 *         {@code null} if no return value is necessary.
	 */
	T onJWSObject(final JWSObject jwsObject, final C context);


	/**
	 * Invoked when the parsed JOSE object is a JWE object.
	 *
	 * @param jweObject The parsed JWE object. Not {@code null}.
	 * @param context   Optional context of the JWE object, {@code null} if
	 *                  not required.
	 *
	 * @return Any object to be used after inspecting the JWE object, or
	 *         {@code null} if no return value is necessary.
	 */
	T onJWEObject(final JWEObject jweObject, final C context);
}

