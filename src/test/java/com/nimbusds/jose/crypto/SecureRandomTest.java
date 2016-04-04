package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import junit.framework.TestCase;


/**
 * Times secure random initialisation.
 */
public class SecureRandomTest extends TestCase {


	public void testDefault()
		throws NoSuchAlgorithmException {

		final long startTime = System.nanoTime();

		SecureRandom sr = new SecureRandom();

		final long endTime = System.nanoTime();

		// Uncomment to print out result
		// System.out.println("Default secure random algorithm for this platform: " + sr.getAlgorithm());
		// System.out.println(sr.getAlgorithm() + " initialisation time: " + (endTime - startTime) + "ns");
	}


	public void testSHA1PRNGTime()
		throws NoSuchAlgorithmException {

		final long startTime = System.nanoTime();

		SecureRandom.getInstance("SHA1PRNG");

		final long endTime = System.nanoTime();

		// Uncomment to print out result
		// System.out.println("SHA1PRNG initialisation time: " + (endTime - startTime) + "ns");
	}
}
