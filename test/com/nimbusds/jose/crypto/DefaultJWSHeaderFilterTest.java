package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeaderFilter;


/**
 * Tests the default JWS header filter implementation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-05)
 */
public class DefaultJWSHeaderFilterTest extends TestCase {


	public void testRun() {

		Set<JWSAlgorithm> supportedAlgs = new HashSet<JWSAlgorithm>();
		supportedAlgs.add(JWSAlgorithm.HS256);
		supportedAlgs.add(JWSAlgorithm.HS384);
		supportedAlgs.add(JWSAlgorithm.HS512);
		
		Set<String> acceptedParams = new HashSet<String>();
		acceptedParams.add("alg");
		acceptedParams.add("typ");
		acceptedParams.add("cty");

		DefaultJWSHeaderFilter filter = new DefaultJWSHeaderFilter(supportedAlgs, acceptedParams);
		
		assertEquals(3, filter.supportedAlgorithms().size());
		assertTrue(filter.supportedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(filter.supportedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(filter.supportedAlgorithms().contains(JWSAlgorithm.HS512));
		
		assertEquals(3, filter.getAcceptedAlgorithms().size());
		assertTrue(filter.getAcceptedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(filter.getAcceptedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(filter.getAcceptedAlgorithms().contains(JWSAlgorithm.HS512));
		
		assertEquals(3, filter.getAcceptedParameters().size());
		assertTrue(filter.getAcceptedParameters().contains("alg"));
		assertTrue(filter.getAcceptedParameters().contains("typ"));
		assertTrue(filter.getAcceptedParameters().contains("cty"));
		
		// Limit accepted algs to HS512 only
		Set<JWSAlgorithm> acceptedAlgs = new HashSet<JWSAlgorithm>();
		acceptedAlgs.add(JWSAlgorithm.HS512);
		
		filter.setAcceptedAlgorithms(acceptedAlgs);
		assertEquals(1, filter.getAcceptedAlgorithms().size());
		assertTrue(filter.getAcceptedAlgorithms().contains(JWSAlgorithm.HS512));
		
		
		acceptedAlgs.add(JWSAlgorithm.RS512);
		
		try {
			filter.setAcceptedAlgorithms(acceptedAlgs);
			
			fail("Failed to raise IllegalArgumentException");
		
		} catch (IllegalArgumentException e) {
		
			// ok
		}
	}
}
