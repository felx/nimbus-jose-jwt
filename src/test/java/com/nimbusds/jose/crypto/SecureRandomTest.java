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
