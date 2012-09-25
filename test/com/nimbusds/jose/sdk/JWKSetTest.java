package com.nimbusds.jose.sdk;


import java.text.ParseException;

import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Tests JSON Web Key (JWK) set parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-25)
 */
public class JWKSetTest extends TestCase {


	public void testParse() {
	
		// The string is from the JWK spec
		String s =
			"{\"keys\":" +
     			    "[" +
			       "{\"alg\":\"EC\"," +
        			"\"crv\":\"P-256\"," +
        			"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
        			"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
        			"\"use\":\"enc\"," +
        			"\"kid\":\"1\"}," +
                        	" " +
			       "{\"alg\":\"RSA\"," +
        			"\"mod\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			   "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			   "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			   "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			   "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			   "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
        			"\"exp\":\"AQAB\"," +
        			"\"kid\":\"2011-04-29\"}" +
			     "]" +
			   "}";
   
   		JWKSet keySet = null;
		
		try {
			keySet = JWKSet.parse(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		List<JWK> keyList = keySet.getKeys();
		
		assertNotNull(keyList);
		
		assertEquals(2, keyList.size());
		
		JWK key = keyList.get(0);
		
		assertNotNull(key);
		
		assertTrue(key instanceof ECKey);
		
		assertEquals("1", key.getKeyID());
		assertEquals(Use.ENCRYPTION, key.getKeyUse());
		
		ECKey ecKey = (ECKey)key;
		
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
	
	
		key = keyList.get(1);
		
		assertNotNull(key);
		
		assertTrue(key instanceof RSAKey);
		
		assertEquals("2011-04-29", key.getKeyID());
		assertNull(key.getKeyUse());
		
		RSAKey rsaKey = (RSAKey)key;
		
		assertEquals("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			     "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			     "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			     "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			     "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			     "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 
			     rsaKey.getModulus().toString());
			     
		assertEquals("AQAB", rsaKey.getExponent().toString());
	}
	
	
	public void testSerializeAndParse() {
	
		
		ECKey ecKey = new ECKey(ECKey.Curve.P_256, 
		                        new Base64URL("abc"), 
					new Base64URL("def"),
					Use.ENCRYPTION,
					"1234");
		
		RSAKey rsaKey = new RSAKey(new Base64URL("abc"),
		                           new Base64URL("def"),
					   Use.SIGNATURE,
					   "5678");
		
		JWKSet keySet = new JWKSet();
		
		keySet.getKeys().add(ecKey);
		keySet.getKeys().add(rsaKey);
		
		String s = keySet.toString();
		
		
		try {
			keySet = JWKSet.parse(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(keySet);
		assertEquals(2, keySet.getKeys().size());
		
		ecKey = (ECKey)keySet.getKeys().get(0);
		assertNotNull(ecKey);
		assertEquals(ECKey.Curve.P_256, ecKey.getCurve());
		assertEquals("abc", ecKey.getX().toString());
		assertEquals("def", ecKey.getY().toString());
		assertEquals(Use.ENCRYPTION, ecKey.getKeyUse());
		assertEquals("1234", ecKey.getKeyID());
		
		rsaKey = (RSAKey)keySet.getKeys().get(1);
		assertNotNull(rsaKey);
		assertEquals("abc", rsaKey.getModulus().toString());
		assertEquals("def", rsaKey.getExponent().toString());
		assertEquals(Use.SIGNATURE, rsaKey.getKeyUse());
		assertEquals("5678", rsaKey.getKeyID());
	}
}
