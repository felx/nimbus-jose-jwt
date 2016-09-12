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

package com.nimbusds.jose.proc;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;


/**
 * Tests the JOSE object / header matcher.
 */
public class JOSEMatcherTest extends TestCase {


	public void testMinimalConstructor() {

		JOSEMatcher matcher = new JOSEMatcher(null, null, null, null, null);

		assertNull(matcher.getJOSEClasses());
		assertNull(matcher.getAlgorithms());
		assertNull(matcher.getEncryptionMethods());
		assertNull(matcher.getJWKURLs());
		assertNull(matcher.getKeyIDs());
	}


	public void testAllSetConstuctor()
		throws URISyntaxException {

		Set<Class<? extends JOSEObject>> classes = new HashSet<>();
		classes.add(PlainObject.class);
		classes.add(JWSObject.class);
		classes.add(JWEObject.class);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(Algorithm.NONE);
		algs.add(JWSAlgorithm.HS256);

		Set<EncryptionMethod> encs = new HashSet<>();
		encs.add(EncryptionMethod.A128CBC_HS256);

		Set<URI> jkus = new HashSet<>();
		jkus.add(new URI("https://c2id.com/jwk.json"));
		jkus.add(new URI("https://demo.c2id.com/jwk.json"));

		Set<String> kids = new HashSet<>();
		kids.add("1");
		kids.add("2");

		JOSEMatcher matcher = new JOSEMatcher(classes, algs, encs, jkus, kids);

		assertEquals(classes, matcher.getJOSEClasses());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(encs, matcher.getEncryptionMethods());
		assertEquals(jkus, matcher.getJWKURLs());
		assertEquals(kids, matcher.getKeyIDs());
	}


	public void testBuilderWithSets()
		throws URISyntaxException {

		Set<Class<? extends JOSEObject>> classes = new HashSet<>();
		classes.add(PlainObject.class);
		classes.add(JWSObject.class);
		classes.add(JWEObject.class);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(Algorithm.NONE);
		algs.add(JWSAlgorithm.HS256);

		Set<EncryptionMethod> encs = new HashSet<>();
		encs.add(EncryptionMethod.A128CBC_HS256);

		Set<URI> jkus = new HashSet<>();
		jkus.add(new URI("https://c2id.com/jwk.json"));
		jkus.add(new URI("https://demo.c2id.com/jwk.json"));

		Set<String> kids = new HashSet<>();
		kids.add("1");
		kids.add("2");

		JOSEMatcher matcher = new JOSEMatcher.Builder()
			.joseClasses(classes)
			.algorithms(algs)
			.encryptionMethods(encs)
			.jwkURLs(jkus)
			.keyIDs(kids)
			.build();

		assertEquals(classes, matcher.getJOSEClasses());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(encs, matcher.getEncryptionMethods());
		assertEquals(jkus, matcher.getJWKURLs());
		assertEquals(kids, matcher.getKeyIDs());
	}


	public void testBuilderWithVarArgs()
		throws URISyntaxException {

		JOSEMatcher matcher = new JOSEMatcher.Builder()
			.joseClasses(PlainObject.class, JWSObject.class)
			.algorithms(Algorithm.NONE, JWSAlgorithm.HS256)
			.encryptionMethods(EncryptionMethod.A128CBC_HS256)
			.jwkURLs(new URI("https://c2id.com/jwk.json"), new URI("https://demo.c2id.com/jwk.json"), null)
			.keyIDs("1", "2", null)
			.build();

		assertTrue(matcher.getJOSEClasses().contains(PlainObject.class));
		assertTrue(matcher.getJOSEClasses().contains(JWSObject.class));
		assertEquals(2, matcher.getJOSEClasses().size());

		assertTrue(matcher.getAlgorithms().contains(Algorithm.NONE));
		assertTrue(matcher.getAlgorithms().contains(JWSAlgorithm.HS256));
		assertEquals(2, matcher.getAlgorithms().size());

		assertTrue(matcher.getEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertEquals(1, matcher.getEncryptionMethods().size());

		assertTrue(matcher.getJWKURLs().contains(new URI("https://c2id.com/jwk.json")));
		assertTrue(matcher.getJWKURLs().contains(new URI("https://demo.c2id.com/jwk.json")));
		assertTrue(matcher.getJWKURLs().contains(null));
		assertEquals(3, matcher.getJWKURLs().size());

		assertTrue(matcher.getKeyIDs().contains("1"));
		assertTrue(matcher.getKeyIDs().contains("2"));
		assertTrue(matcher.getKeyIDs().contains(null));
		assertEquals(3, matcher.getKeyIDs().size());
	}


	public void testBuilderWithSingleArgs()
		throws URISyntaxException {

		JOSEMatcher matcher = new JOSEMatcher.Builder()
			.joseClass(JWSObject.class)
			.algorithm(JWSAlgorithm.HS256)
			.encryptionMethod(EncryptionMethod.A128CBC_HS256)
			.jwkURL(new URI("https://c2id.com/jwk.json"))
			.keyID("1")
			.build();

		assertTrue(matcher.getJOSEClasses().contains(JWSObject.class));
		assertEquals(1, matcher.getJOSEClasses().size());

		assertTrue(matcher.getAlgorithms().contains(JWSAlgorithm.HS256));
		assertEquals(1, matcher.getAlgorithms().size());

		assertTrue(matcher.getEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertEquals(1, matcher.getEncryptionMethods().size());

		assertTrue(matcher.getJWKURLs().contains(new URI("https://c2id.com/jwk.json")));
		assertEquals(1, matcher.getJWKURLs().size());

		assertTrue(matcher.getKeyIDs().contains("1"));
		assertEquals(1, matcher.getKeyIDs().size());
	}


	public void testMatchClass() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().joseClass(JWSObject.class).build();

		// JOSE
		assertTrue(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
		assertFalse(matcher.matches(new PlainObject(new Payload("Hello world!"))));

		// JWT
		assertTrue(matcher.matches(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build())));
		assertFalse(matcher.matches(new PlainJWT(new JWTClaimsSet.Builder().build())));
	}


	public void testMatchAnyClass() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().joseClass(null).build();

		// JOSE
		assertTrue(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
		assertTrue(matcher.matches(new PlainObject(new Payload("Hello world!"))));

		// JWT
		assertTrue(matcher.matches(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build())));
		assertTrue(matcher.matches(new PlainJWT(new JWTClaimsSet.Builder().build())));
	}


	public void testMatchAlg() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().algorithm(JWSAlgorithm.HS256).build();

		assertTrue(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
		assertFalse(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("Hello world!"))));
	}


	public void testMatchAnyAlg() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().algorithm(null).build();

		assertTrue(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
	}


	public void testMatchEnc() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().encryptionMethod(EncryptionMethod.A128GCM).build();

		assertTrue(matcher.matches(new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new Payload("Hello world!"))));
		assertFalse(matcher.matches(new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload("Hello world!"))));
		assertFalse(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
	}


	public void testMatchAnyEnc() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().encryptionMethod(null).build();

		assertTrue(matcher.matches(new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new Payload("Hello world!"))));
		assertTrue(matcher.matches(new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload("Hello world!"))));
		assertTrue(matcher.matches(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello world!"))));
	}


	public void testMatchJKU()
		throws Exception {

		JOSEMatcher matcher = new JOSEMatcher.Builder().jwkURL(new URI("https://c2id.com/jwk.json")).build();

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).jwkURL(new URI("https://c2id.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertTrue(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).jwkURL(new URI("https://c2id.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertFalse(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).jwkURL(new URI("https://example.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertFalse(matcher.matches(new PlainObject(
			new PlainHeader.Builder().customParam("jku", "https://c2id.com/jwk.json").build(),
			new Payload("Hello world!"))));
	}


	public void testMatchAnyJKU()
		throws Exception {

		JOSEMatcher matcher = new JOSEMatcher.Builder().jwkURL(null).build();

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).jwkURL(new URI("https://c2id.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertTrue(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).jwkURL(new URI("https://c2id.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).jwkURL(new URI("https://example.com/jwk.json")).build(),
			new Payload("Hello world!"))));

		assertTrue(matcher.matches(new PlainObject(
			new PlainHeader.Builder().customParam("jku", "https://c2id.com/jwk.json").build(),
			new Payload("Hello world!"))));
	}


	public void testMatchKID() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().keyID("1").build();

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(),
			new Payload("Hello world!")
		)));

		assertTrue(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("1").build(),
			new Payload("Hello world!")
		)));

		assertFalse(matcher.matches(new PlainObject(
			new PlainHeader.Builder().customParam("kid", "1").build(),
			new Payload("Hello world!")
		)));

		assertFalse(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("2").build(),
			new Payload("Hello world!")
		)));

		assertFalse(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("2").build(),
			new Payload("Hello world!")
		)));
	}


	public void testMatchAnyKID() {

		JOSEMatcher matcher = new JOSEMatcher.Builder().keyID(null).build();

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(),
			new Payload("Hello world!")
		)));

		assertTrue(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("1").build(),
			new Payload("Hello world!")
		)));

		assertTrue(matcher.matches(new PlainObject(
			new PlainHeader.Builder().customParam("kid", "1").build(),
			new Payload("Hello world!")
		)));

		assertTrue(matcher.matches(new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("2").build(),
			new Payload("Hello world!")
		)));

		assertTrue(matcher.matches(new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("2").build(),
			new Payload("Hello world!")
		)));
	}
}
