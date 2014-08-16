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
public class CriticalHeaderParameterCheckerTest extends TestCase {


	public void testConstructor() {

		CriticalHeaderParameterChecker checker = new CriticalHeaderParameterChecker();

		assertTrue(checker.getIgnoredCriticalHeaders().isEmpty());
	}


	public void testSetter() {

		CriticalHeaderParameterChecker checker = new CriticalHeaderParameterChecker();

		checker.setIgnoredCriticalHeaders(new HashSet<String>(Arrays.asList("exp", "hs")));

		assertTrue(checker.getIgnoredCriticalHeaders().contains("exp"));
		assertTrue(checker.getIgnoredCriticalHeaders().contains("hs"));

		assertEquals(2, checker.getIgnoredCriticalHeaders().size());
	}


	public void testPassMissingCritHeader() {

		CriticalHeaderParameterChecker checker = new CriticalHeaderParameterChecker();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build();

		assertTrue(checker.headerPasses(header));
	}


	public void testPassIgnoredCritParams() {

		CriticalHeaderParameterChecker checker = new CriticalHeaderParameterChecker();
		checker.getIgnoredCriticalHeaders().add("exp");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			customParameter("exp", "2014-04-24").
			criticalHeaders(new HashSet<String>(Arrays.asList("exp"))).
			build();

		assertTrue(checker.headerPasses(header));
	}


	public void testReject() {

		CriticalHeaderParameterChecker checker = new CriticalHeaderParameterChecker();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			customParameter("exp", "2014-04-24").
			criticalHeaders(new HashSet<String>(Arrays.asList("exp"))).
			build();

		assertFalse(checker.headerPasses(header));
	}
}
