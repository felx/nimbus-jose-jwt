package com.nimbusds.jose.sdk;


import junit.framework.TestCase;

import com.nimbusds.jose.sdk.util.Base64URL;


import java.text.ParseException;


/**
 * Tests JOSE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
public class JOSEObjectTest extends TestCase {


	public void testSplitThreeParts() {
		
		// Implies JWS
		String s = "abc.def.ghi";
		
		Base64URL[] parts = null;
		
		try {
			parts = JOSEObject.split(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}
	
	
	public void testSplitFourParts() {

		// Implies JWE
		String s = "abc.def.ghi.jkl";
		
		Base64URL[] parts = null;
		
		try {
			parts = JOSEObject.split(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(4, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
		assertEquals("jkl", parts[3].toString());
	}
	
	
	public void testSplitEmptyThirdPart() {

		// Implies plain JOSE object
		String s = "abc.def.";
		
		Base64URL[] parts = null;
		
		try {
			parts = JOSEObject.split(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("", parts[2].toString());
	}
	
	
	public void testSplitEmptySecondPart() {

		// JWS with empty payload
		String s = "abc..ghi";
		
		Base64URL[] parts = null;
		
		try {
			parts = JOSEObject.split(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}
	
	
	public void testSplitException() {

		// Illegal JOSE
		String s = "abc.def";
		
		Base64URL[] parts = null;
		
		try {
			parts = JOSEObject.split(s);
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
		}
	}
}
