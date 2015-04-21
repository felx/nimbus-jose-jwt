package com.nimbusds.jose.crypto;


import java.util.Arrays;
import java.util.HashSet;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import junit.framework.TestCase;


/**
 * Tests the critical parameters checker.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
public class CriticalHeaderParamsDeferralTest extends TestCase {


	public void testConstructor() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		assertTrue(checker.getIgnoredCriticalHeaders().isEmpty());
	}


	public void testSetter() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		checker.setIgnoredCriticalHeaders(new HashSet<>(Arrays.asList("exp", "hs")));

		assertTrue(checker.getIgnoredCriticalHeaders().contains("exp"));
		assertTrue(checker.getIgnoredCriticalHeaders().contains("hs"));

		assertEquals(2, checker.getIgnoredCriticalHeaders().size());
	}


	public void testPassMissingCritHeader() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build();

		assertTrue(checker.headerPasses(header));
	}


	public void testPassIgnoredCritParams() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();
		checker.getIgnoredCriticalHeaders().add("exp");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		assertTrue(checker.headerPasses(header));
	}


	public void testReject() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		assertFalse(checker.headerPasses(header));
	}
}
