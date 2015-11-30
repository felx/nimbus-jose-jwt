package com.nimbusds.jwt.util;


import java.util.Date;

import junit.framework.TestCase;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest extends TestCase {


	public void testToSeconds() {

		final Date date = new Date(2000l);

		assertEquals(2, DateUtils.toSecondsSinceEpoch(date));
	}


	public void testFromSeconds() {

		assertTrue(new Date(2000l).equals(DateUtils.fromSecondsSinceEpoch(2)));
	}


	public void testRoundTrip() {

		final Date date = new Date(100000);

		final long ts = DateUtils.toSecondsSinceEpoch(date);

		assertTrue(date.equals(DateUtils.fromSecondsSinceEpoch(ts)));
	}


	public void testAfterNoClockSkew_true() {

		final Date date = new Date(100001L);
		final Date reference = new Date(100000L);
		assertTrue(DateUtils.isAfter(date, reference, 0L));
	}


	public void testAfterNoClockSkew_false() {

		final Date date = new Date(100000L);
		final Date reference = new Date(100001L);
		assertFalse(DateUtils.isAfter(date, reference, 0L));
	}


	public void testBeforeNoClockSkew_true() {

		final Date date = new Date(100000L);
		final Date reference = new Date(100001L);
		assertTrue(DateUtils.isBefore(date, reference, 0L));
	}


	public void testBeforeNoClockSkew_false() {

		final Date date = new Date(100001L);
		final Date reference = new Date(100000L);
		assertFalse(DateUtils.isBefore(date, reference, 0L));
	}


	public void testAfterWithClockSkew_true() {

		final Date date = new Date(2000L);
		final Date reference = new Date(2999L);
		final long skewSeconds = 1L;
		assertTrue(DateUtils.isAfter(date, reference, skewSeconds));
	}


	public void testAfterWithClockSkew_false() {

		final Date date = new Date(2000L);
		final Date reference = new Date(3000L);
		final long skewSeconds = 1L;
		assertFalse(DateUtils.isAfter(date, reference, skewSeconds));
	}


	public void testBeforeWithClockSkew_true() {

		final Date date = new Date(2000L);
		final Date reference = new Date(1001L);
		final long skewSeconds = 1L;
		assertTrue(DateUtils.isBefore(date, reference, skewSeconds));
	}


	public void testBeforeWithClockSkew_false() {

		final Date date = new Date(2000L);
		final Date reference = new Date(1000L);
		final long skewSeconds = 1L;
		assertFalse(DateUtils.isBefore(date, reference, skewSeconds));
	}


	public void testNotBefore() {

		final long skewSeconds = 1L;

		assertTrue(DateUtils.isAfter(new Date(4001L), new Date(5000L), skewSeconds));
		assertTrue(DateUtils.isAfter(new Date(5000L), new Date(5000L), skewSeconds));
		assertTrue(DateUtils.isAfter(new Date(6000L), new Date(5000L), skewSeconds));
		assertFalse(DateUtils.isAfter(new Date(4000L), new Date(5000L), skewSeconds));
	}
}
