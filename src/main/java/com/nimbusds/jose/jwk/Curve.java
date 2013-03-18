package com.nimbusds.jose.jwk;


import java.text.ParseException;

import net.jcip.annotations.Immutable;


/**
 * Cryptographic curve. This class is immutable.
 *
 * <p>Includes constants for the following standard cryptographic curves:
 *
 * <ul>
 *     <li>{@link #P_256}
 *     <li>{@link #P_384}
 *     <li>{@link #P_521}
 * </ul>
 *
 * <p>See "Digital Signature Standard (DSS)", FIPS PUB 186-3, June 2009, 
 * National Institute of Standards and Technology (NIST).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-17)
 */
@Immutable
public final class Curve {


	/**
	 * P-256 curve.
	 */
	public static final Curve P_256 = new Curve("P-256");


	/**
	 * P-384 curve.
	 */
	public static final Curve P_384 = new Curve("P-384");


	/**
	 * P-521 curve.
	 */
	public static final Curve P_521 = new Curve("P-521");


	/**
	 * The curve name.
	 */
	private final String name;


	/**
	 * Creates a new cryptographic curve with the specified name.
	 *
	 * @param name The name of the cryptographic curve. Must not be
	 *             {@code null}.
	 */
	public Curve(final String name) {

		if (name == null) {
			throw new IllegalArgumentException("The cryptographic curve name must not be null");
		}

		this.name = name;
	}


	/**
	 * Gets the name of this cryptographic curve.
	 *
	 * @return The name.
	 */
	public String getName() {

		return name;
	}


	/**
	 * @see #getName
	 */
	@Override
	public String toString() {

		return getName();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value,
	 *         otherwise {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object != null && 
		       object instanceof Curve && 
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses a cryptographic curve from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The cryptographic curve.
	 *
	 * @throws ParseException If the string couldn't be parsed.
	 */
	public static Curve parse(final String s) 
		throws ParseException {

		if (s == null) {
			throw new IllegalArgumentException("The cryptographic curve sting must not be null");
		}

		if (s == P_256.getName()) {

			return P_256;

		} else if (s == P_384.getName()) {

			return P_384;

		} else if (s == P_521.getName()) {

			return P_521;

		} else {

			return new Curve(s);
		}
	}
}