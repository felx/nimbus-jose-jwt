package com.nimbusds.jose.crypto;


import java.util.Arrays;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;


/**
 * Tests the critical parameters checker.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-21
 */
public class CriticalHeaderParamsDeferralTest extends TestCase {


	public void testConstructor() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		assertTrue(checker.getProcessedCriticalHeaderParams().isEmpty());
		assertTrue(checker.getDeferredCriticalHeaderParams().isEmpty());
	}


	public void testSetter() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		checker.setDeferredCriticalHeaderParams(new HashSet<>(Arrays.asList("exp", "hs")));

		assertTrue(checker.getDeferredCriticalHeaderParams().contains("exp"));
		assertTrue(checker.getDeferredCriticalHeaderParams().contains("hs"));
		assertEquals(2, checker.getDeferredCriticalHeaderParams().size());
	}


	public void testPassMissingCritHeader() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build();

		assertTrue(checker.headerPasses(header));
	}


	public void testPassIgnoredCritParams() {

		CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();
		checker.setDeferredCriticalHeaderParams(new HashSet<>(Arrays.asList("exp")));

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
