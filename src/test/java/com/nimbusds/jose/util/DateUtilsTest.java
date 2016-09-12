/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.util;


import java.util.Date;

import com.nimbusds.jose.util.DateUtils;
import junit.framework.TestCase;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest extends TestCase {


	public void testToSeconds() {

		final Date date = new Date(2000L);

		assertEquals(2, DateUtils.toSecondsSinceEpoch(date));
	}


	public void testFromSeconds() {

		assertTrue(new Date(2000L).equals(DateUtils.fromSecondsSinceEpoch(2)));
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


	public void testForEXPClaim() {

		final Date now = new Date();

		final Date exp = new Date(now.getTime() - 30*1000L); // 30 seconds behind

		boolean valid = DateUtils.isAfter(exp, now, 60);
		assertTrue(valid);
	}


	public void testForIATClaim() {

		final Date now = new Date();

		final Date iat = new Date(now.getTime() + 30*1000L); // 30 seconds ahead

		boolean valid = DateUtils.isBefore(iat, now, 60);
		assertTrue(valid);
	}
}
