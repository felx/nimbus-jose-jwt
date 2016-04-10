package com.nimbusds.jose.jwk.sourcing;


import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import static net.jadler.Jadler.*;

import com.nimbusds.jose.jwk.*;
import junit.framework.TestCase;
import net.jadler.Request;
import net.jadler.stubbing.Responder;
import net.jadler.stubbing.StubResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class RemoteJWKSetTest extends TestCase {



	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testSelectRSAByKeyID_defaultRetriever()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		String id = "https://c2id.com";
		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jwkSet.toJSONObject(true).toJSONString());

		RemoteJWKSet jwkSetSource = new RemoteJWKSet(jwkSetURL, null);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());

		JWKSet out = jwkSetSource.getJWKSet();
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	@Test
	public void testRefreshRSAByKeyID_defaultRetriever()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK3 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("3")
			.build();

		String id = "https://c2id.com";
		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respondUsing(new Responder() {
				private int count = 0;
				@Override
				public StubResponse nextResponse(Request request) {

					if (! request.getMethod().equalsIgnoreCase("GET")) {
						return StubResponse.builder().status(405).build();
					}

					if (count == 0) {
						++count;
						return StubResponse.builder()
							.status(200)
							.header("Content-Type", "application/json")
							.body(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2)).toJSONObject().toJSONString(), Charset.forName("UTF-8"))
							.build();
					}

					// Add 3rd key
					return StubResponse.builder()
						.status(200)
						.header("Content-Type", "application/json")
						.body(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2, (JWK)rsaJWK3)).toJSONObject().toJSONString(), Charset.forName("UTF-8"))
						.build();
				}
			});

		RemoteJWKSet jwkSetSource = new RemoteJWKSet(jwkSetURL, null);

		Thread initialRetriever = getThreadByName("initial-jwk-set-retriever["+ jwkSetURL +"]");
		assertNotNull(initialRetriever);
		initialRetriever.join();

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());

		JWKSet out = jwkSetSource.getJWKSet();
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// Select 3rd key, expect refresh of JWK set
		matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("3").build()), null);

		m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK3.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK3.getModulus(), m1.getModulus());
		assertEquals("3", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	private static Thread getThreadByName(String threadName) {
		for (Thread t : Thread.getAllStackTraces().keySet()) {
			if (t.getName().equals(threadName)) return t;
		}
		return null;
	}


	@Test
	public void testInvalidJWKSetURL()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		String id = "https://c2id.com";
		URL jwkSetURL = new URL("http://localhost:" + port() + "/invalid-path");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jwkSet.toJSONObject(true).toJSONString());

		RemoteJWKSet jwkSetSource = new RemoteJWKSet(jwkSetURL, null);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());

		assertNull(jwkSetSource.getJWKSet());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		assertTrue(matches.isEmpty());
	}
}
