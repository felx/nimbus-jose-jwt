package com.nimbusds.jwt.util;


import java.util.Date;


/**
 * Date utilities.
 */
public class DateUtils {


	/**
	 * Converts the specified date object to a Unix epoch time in seconds.
	 *
	 * @param date The date. Must not be {@code null}.
	 *
	 * @return The Unix epoch time, in seconds.
	 */
	public static long toSecondsSinceEpoch(final Date date) {

		return date.getTime() / 1000L;
	}


	/**
	 * Converts the specified Unix epoch time in seconds to a date object.
	 *
	 * @param time The Unix epoch time, in seconds. Must not be negative.
	 *
	 * @return The date.
	 */
	public static Date fromSecondsSinceEpoch(final long time) {

		return new Date(time * 1000L);
	}


	/**
	 * Check if the specified date is after the specified reference, given
	 * the maximum accepted clock skew.
	 *
	 * <p>Formula:
	 *
	 * <pre>
	 * return date +/- clock_skew > reference
	 * </pre>
	 *
	 * @param date                The date to check. Must not be
	 *                            {@code null}.
	 * @param reference           The reference date. Must not be
	 *                            {@code null}.
	 * @param maxClockSkewSeconds The maximum acceptable clock skew of the
	 *                            date value to check, in seconds.
	 *
	 * @return {@code true} if the date is before the reference, plus or
	 *         minus the maximum accepted clock skew, else {@code false}.
	 */
	public static boolean isAfter(final Date date,
				      final Date reference,
				      final long maxClockSkewSeconds) {

		return new Date(date.getTime() + maxClockSkewSeconds*1000L).after(reference);
	}


	/**
	 * Checks if the specified data is before the specified reference,
	 * given the maximum accepted clock skew.
	 *
	 * <p>Formula:
	 *
	 * <pre>
	 * return date +/- clock_skew < reference
	 * </pre>
	 *
	 * @param date                The date to check. Must not be
	 *                            {@code null}.
	 * @param reference           The reference date. Must not be
	 *                            {@code null}.
	 * @param maxClockSkewSeconds The maximum acceptable clock skew of the
	 *                            date value to check, in seconds.
	 *
	 * @return {@code true} if the date is before the reference, plus or
	 *         minus the maximum accepted clock skew, else {@code false}.
	 */
	public static boolean isBefore(final Date date,
				       final Date reference,
				       final long maxClockSkewSeconds) {

		return new Date(date.getTime() - maxClockSkewSeconds*1000L).before(reference);
	}


	/**
	 * Prevents instantiation.
	 */
	private DateUtils() { }
}
