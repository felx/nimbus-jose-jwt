package com.nimbusds.jose;


import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;


/**
 * Tests the default JWE header filter implementation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
public class DefaultJWEHeaderFilterTest extends TestCase {


	public void testDefaultAcceptedParameters() {

		Set<JWEAlgorithm> supportedAlgs = new HashSet<JWEAlgorithm>();
		supportedAlgs.add(JWEAlgorithm.RSA1_5);
		supportedAlgs.add(JWEAlgorithm.RSA_OAEP);

		Set<EncryptionMethod> supportedEncs = new HashSet<EncryptionMethod>();
		supportedEncs.add(EncryptionMethod.A128GCM);
		supportedEncs.add(EncryptionMethod.A256GCM);

		DefaultJWEHeaderFilter filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs);

		assertEquals(2, filter.supportedAlgorithms().size());
		assertTrue(filter.supportedAlgorithms().contains(JWEAlgorithm.RSA1_5));
		assertTrue(filter.supportedAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		assertEquals(2, filter.supportedEncryptionMethods().size());
		assertTrue(filter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(filter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));

		assertTrue(filter.getAcceptedParameters().containsAll(JWEHeader.getRegisteredParameterNames()));
		assertEquals(filter.getAcceptedParameters().size(), JWEHeader.getRegisteredParameterNames().size());
	}


	public void testMinimumAcceptedParameters() {

		Set<JWEAlgorithm> supportedAlgs = new HashSet<JWEAlgorithm>();
		supportedAlgs.add(JWEAlgorithm.RSA1_5);
		supportedAlgs.add(JWEAlgorithm.RSA_OAEP);

		Set<EncryptionMethod> supportedEncs = new HashSet<EncryptionMethod>();
		supportedEncs.add(EncryptionMethod.A128GCM);
		supportedEncs.add(EncryptionMethod.A256GCM);

		Set<String> acceptedParams = new HashSet<String>();

		DefaultJWEHeaderFilter filter = null;

		try {
			filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs, acceptedParams);

			fail("Failed to raise IllegalArgumentException");
			
		} catch (IllegalArgumentException e) {

			// ok
		}

		acceptedParams = new HashSet<String>();
		acceptedParams.add("alg");

		try {
			filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs, acceptedParams);

			fail("Failed to raise IllegalArgumentException");
			
		} catch (IllegalArgumentException e) {

			// ok
		}


		acceptedParams = new HashSet<String>();
		acceptedParams.add("enc");

		try {
			filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs, acceptedParams);

			fail("Failed to raise IllegalArgumentException");
			
		} catch (IllegalArgumentException e) {

			// ok
		}


		acceptedParams = new HashSet<String>();
		acceptedParams.add("alg");
		acceptedParams.add("enc");

		// ok
		filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs, acceptedParams);
	}


	public void testRun() {

		Set<JWEAlgorithm> supportedAlgs = new HashSet<JWEAlgorithm>();
		supportedAlgs.add(JWEAlgorithm.RSA1_5);
		supportedAlgs.add(JWEAlgorithm.RSA_OAEP);

		Set<EncryptionMethod> supportedEncs = new HashSet<EncryptionMethod>();
		supportedEncs.add(EncryptionMethod.A128GCM);
		supportedEncs.add(EncryptionMethod.A256GCM);

		Set<String> acceptedParams = new HashSet<String>();
		acceptedParams.add("alg");
		acceptedParams.add("enc");
		acceptedParams.add("typ");
		acceptedParams.add("cty");

		DefaultJWEHeaderFilter filter = new DefaultJWEHeaderFilter(supportedAlgs, supportedEncs, acceptedParams);

		assertEquals(2, filter.supportedAlgorithms().size());
		assertTrue(filter.supportedAlgorithms().contains(JWEAlgorithm.RSA1_5));
		assertTrue(filter.supportedAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		assertEquals(2, filter.getAcceptedAlgorithms().size());
		assertTrue(filter.getAcceptedAlgorithms().contains(JWEAlgorithm.RSA1_5));
		assertTrue(filter.getAcceptedAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		assertEquals(2, filter.supportedEncryptionMethods().size());
		assertTrue(filter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(filter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));

		assertEquals(2, filter.getAcceptedEncryptionMethods().size());
		assertTrue(filter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(filter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A256GCM));

		assertEquals(4, filter.getAcceptedParameters().size());
		assertTrue(filter.getAcceptedParameters().contains("alg"));
		assertTrue(filter.getAcceptedParameters().contains("enc"));
		assertTrue(filter.getAcceptedParameters().contains("typ"));
		assertTrue(filter.getAcceptedParameters().contains("cty"));

		// Limit accepted algs to RSA-OEAP only
		Set<JWEAlgorithm> acceptedAlgs = new HashSet<JWEAlgorithm>();
		acceptedAlgs.add(JWEAlgorithm.RSA_OAEP);

		filter.setAcceptedAlgorithms(acceptedAlgs);
		assertEquals(1, filter.getAcceptedAlgorithms().size());
		assertTrue(filter.getAcceptedAlgorithms().contains(JWEAlgorithm.RSA_OAEP));


		acceptedAlgs.add(JWEAlgorithm.A128KW);

		try {
			filter.setAcceptedAlgorithms(acceptedAlgs);

			fail("Failed to raise IllegalArgumentException");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}
}
