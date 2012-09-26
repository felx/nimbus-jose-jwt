package com.nimbusds.jose.sdk;


import junit.framework.TestCase;


/**
 * Tests the base Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
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
