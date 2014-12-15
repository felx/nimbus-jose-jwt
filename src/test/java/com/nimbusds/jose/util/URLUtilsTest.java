package com.nimbusds.jose.util;


import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;

import org.apache.commons.lang.RandomStringUtils;


/**
 * Tests the URL utility class.
 */
public class URLUtilsTest extends TestCase {


	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testSuccess()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withBody("Hello world!")
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("text/plain");

		assertEquals("Hello world!", URLUtils.read(new URL("http://localhost:" + port()), 0, 0, -1));
	}


	@Test
	public void testLimitSize()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withBody(RandomStringUtils.randomAlphanumeric(100))
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("text/plain");

		final int sizeLimit = 10;

		String out = URLUtils.read(new URL("http://localhost:" + port()), 0, 0, 10);

		assertEquals(sizeLimit, out.length());
	}


	@Test
	public void testDelay()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withDelay(50, TimeUnit.MILLISECONDS)
			.withStatus(200)
			.withBody("Hello world!")
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("text/plain");

		try {
			URLUtils.read(new URL("http://localhost:" + port()), 10, 10, -1);
			fail();
		} catch (SocketTimeoutException e) {
			assertEquals("Read timed out", e.getMessage());
		}
	}
}
