package com.nimbusds.jose;


/**
 * Handler of parsed {@link JOSEObject}s. Invoked by the
 * {@link JOSEObject#parse(String,JOSEObjectHandler)} method
 * to indicate the exact type of the parsed object - {@link PlainObject plain},
 * {@link JWSObject signed} or {@link JWEObject encrypted object}.
 *
 * @since 3.4
 */
public interface JOSEObjectHandler<T> {


	/**
	 * Invoked when the parsed JOSE object is plain (unsecured).
	 *
	 * @param plainObject The parsed plain JOSE object. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the plain JOSE
	 *         object, or {@code null} if no return value is necessary.
	 */
	public T onPlainObject(final PlainObject plainObject);


	/**
	 * Invoked when the the parsed JOSE object is a JWS object.
	 *
	 * @param jwsObject The parsed JWS object. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the JWS object, or
	 *         {@code null} if no return value is necessary.
	 */
	public T onJWSObject(final JWSObject jwsObject);


	/**
	 * Invoked when the parsed JOSE object is a JWE object.
	 *
	 * @param jweObject The parsed JWE object. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the JWE object, or
	 *         {@code null} if no return value is necessary.
	 */
	public T onJWEObject(final JWEObject jweObject);
}

