package com.nimbusds.jose.handler;


import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.PlainObject;


/**
 * Handler of {@link com.nimbusds.jose.JOSEObject}s.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-22)
 */
public interface JOSEObjectHandler<T, C extends Context> {


	/**
	 * Invoked when the JOSE object is unsecured (plain).
	 *
	 * @param plainObject The unsecured JOSE object. Not {@code null}.
	 * @param context     Optional context of the unsecured JOSE object,
	 *                    {@code null} if not required.
	 *
	 * @return Any object to be used after inspecting the unsecured JOSE
	 *         object, or {@code null} if no return value is necessary.
	 */
	T onPlainObject(final PlainObject plainObject, final C context);


	/**
	 * Invoked when the the JOSE object is a JWS object.
	 *
	 * @param jwsObject The JWS object. Not {@code null}.
	 * @param context   Optional context of the JWS object, {@code null} if
	 *                  not required.
	 *
	 * @return Any object to be used after inspecting the JWS object, or
	 *         {@code null} if no return value is necessary.
	 */
	T onJWSObject(final JWSObject jwsObject, final C context);


	/**
	 * Invoked when the JOSE object is a JWE object.
	 *
	 * @param jweObject The JWE object. Not {@code null}.
	 * @param context   Optional context of the JWE object, {@code null} if
	 *                  not required.
	 *
	 * @return Any object to be used after inspecting the JWE object, or
	 *         {@code null} if no return value is necessary.
	 */
	T onJWEObject(final JWEObject jweObject, final C context);
}

