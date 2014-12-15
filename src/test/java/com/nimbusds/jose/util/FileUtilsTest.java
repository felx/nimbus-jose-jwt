package com.nimbusds.jose.util;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;

import junit.framework.TestCase;


/**
 * Tests the file utility.
 *
 * @author Vladimir Dzhuvinov
 */
public class FileUtilsTest extends TestCase {


	private static final File TEST_FILE = new File("TEST.file.txt");


	@Override
	public void setUp()
		throws Exception {

		PrintWriter out = new PrintWriter(TEST_FILE);
		out.println("Hello world!");
		out.close();
	}


	@Override
	public void tearDown() {

		try {
			Files.delete(TEST_FILE.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	public void testReadNonExisting() {

		try {
			FileUtils.readFile(new File("no-such-file"));
			fail();
		} catch (IOException e) {
			assertTrue(e instanceof FileNotFoundException);
		}
	}


	public void testReadExisting()
		throws Exception {

		assertEquals("Hello world!\n", FileUtils.readFile(TEST_FILE));
	}
}
