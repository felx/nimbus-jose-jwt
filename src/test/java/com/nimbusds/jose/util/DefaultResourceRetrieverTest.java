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

package com.nimbusds.jose.util;


import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.RestrictedResourceRetriever;
import net.minidev.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * Tests the default resource retriever.
 */
public class DefaultResourceRetrieverTest {
	

	@Test
	public void testDefaultSettings() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		assertEquals(0, resourceRetriever.getConnectTimeout());
		assertEquals(0, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());
	}


	@Test
	public void testSetters() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		assertEquals(0, resourceRetriever.getConnectTimeout());
		assertEquals(0, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());

		resourceRetriever.setConnectTimeout(100);
		assertEquals(100, resourceRetriever.getConnectTimeout());

		resourceRetriever.setReadTimeout(200);
		assertEquals(200, resourceRetriever.getReadTimeout());

		resourceRetriever.setSizeLimit(300);
		assertEquals(300, resourceRetriever.getSizeLimit());
	}


	@Test
	public void testTimeoutConstructor() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(100, 200);
		assertEquals(100, resourceRetriever.getConnectTimeout());
		assertEquals(200, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());
	}


	@Test
	public void testFullConstructor() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(100, 200, 300);
		assertEquals(100, resourceRetriever.getConnectTimeout());
		assertEquals(200, resourceRetriever.getReadTimeout());
		assertEquals(300, resourceRetriever.getSizeLimit());
	}


	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testRetrieveOK()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jsonObject.toJSONString());

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testRetrieveOKWithoutContentType()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withBody(jsonObject.toJSONString());

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertNull(resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testIgnoreInvalidContentType()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("A", "B");

		String invalidContentType = "moo/boo/foo";

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withContentType(invalidContentType)
			.withBody(jsonObject.toJSONString());

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();

		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals(invalidContentType, resource.getContentType());
	}


	@Test
	public void testRetrieve2xx()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(201)
			.withHeader("Content-Type", "application/json")
			.withBody(jsonObject.toJSONString());

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testConnectTimeout()
			throws Exception {

		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(50, 0);

		try {
			resourceRetriever.retrieveResource(new URL("http://localhost:" + port + "/c2id/jwks.json"));
			fail();
		} catch (IOException e) {
			assertEquals("Connection refused", e.getMessage());
		}
	}


	@Test
	public void testReadTimeout()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("A", "B");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/c2id/jwks.json")
				.respond()
				.withDelay(100L, TimeUnit.MILLISECONDS)
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(jsonObject.toJSONString());

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 50);

		try {
			resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
			fail();
		} catch (IOException e) {
			assertEquals("Read timed out", e.getMessage());
		}
	}


	@Test
	public void testSizeLimit()
		throws Exception {

		int size = 100000;
		StringBuilder sb = new StringBuilder();
		for (int i=0; i < size; i++) {
			sb.append('a');
		}

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/c2id/jwks.json")
				.respond()
				.withStatus(200)
				.withHeader("Content-Type", "text/plain")
				.withBody(sb.toString());

		int sizeLimit = 50000;
		assertTrue(sizeLimit < size);
		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 0, sizeLimit);

		URL url = new URL("http://localhost:" + port());

		try {
			resourceRetriever.retrieveResource(url);
			fail();
		} catch (FileNotFoundException e) {
			// Size overrun exception poses as file not found
			assertEquals(url.toString(), e.getMessage());
		}
	}
}
