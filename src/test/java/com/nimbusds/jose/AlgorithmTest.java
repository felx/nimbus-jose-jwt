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

package com.nimbusds.jose;


import junit.framework.TestCase;


/**
 * Tests the base Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2012-09-26
 */
public class AlgorithmTest extends TestCase {


	public void testNoneConstant() {

		assertEquals("none", Algorithm.NONE.getName());
		assertEquals(Requirement.REQUIRED, Algorithm.NONE.getRequirement());

		assertEquals(Algorithm.NONE, new Algorithm("none", Requirement.REQUIRED));
	}


	public void testMinimalConstructor() {

		Algorithm alg = new Algorithm("my-alg");

		assertEquals("my-alg", alg.getName());
		assertEquals("my-alg", alg.toString());

		assertNull(alg.getRequirement());
	}


	public void testFullContructor() {

		Algorithm alg = new Algorithm("my-alg", Requirement.OPTIONAL);

		assertEquals("my-alg", alg.getName());
		assertEquals("my-alg", alg.toString());

		assertEquals(Requirement.OPTIONAL, alg.getRequirement());
	}


	public void testEquality() {

		Algorithm alg1 = new Algorithm("my-alg");
		Algorithm alg2 = new Algorithm("my-alg");

		assertTrue(alg1.equals(alg2));
	}


	public void testEqualityDifferentRequirementLevels() {

		Algorithm alg1 = new Algorithm("my-alg", Requirement.REQUIRED);
		Algorithm alg2 = new Algorithm("my-alg", Requirement.OPTIONAL);

		assertTrue(alg1.equals(alg2));
	}


	public void testInequality() {

		Algorithm alg1 = new Algorithm("my-alg");
		Algorithm alg2 = new Algorithm("your-alg");

		assertFalse(alg1.equals(alg2));
	}


	public void testHashCode() {

		Algorithm alg1 = new Algorithm("my-alg");
		Algorithm alg2 = new Algorithm("my-alg");

		assertEquals(alg1.hashCode(), alg2.hashCode());
	}
}
