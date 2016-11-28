/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;


public class BoundedInputStreamTest extends TestCase {
	
	
	private static byte[] createDataArray() {
		
		final int size = 100;
		byte[] data = new byte[size];
		for (int i=0; i<size; i++) {
			data[i] = 1;
		}
		assertEquals(100, data.length);
		return data;
	}
	
	
	public void testUnboundedConstructor() {
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		BoundedInputStream bis = new BoundedInputStream(stream);
		assertEquals(-1L, bis.getLimitBytes());
	}
	

	public void testBounded_readIntoArray_exceed()
		throws Exception {
		
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		
		final int limit = 50;
		
		BoundedInputStream bis = new BoundedInputStream(stream, limit);
		
		assertEquals(limit, bis.getLimitBytes());
		
		byte[] readData = new byte[data.length];
		
		try {
			bis.read(readData);
			fail();
		} catch (IOException e) {
			assertEquals("Exceeded configured input limit of 50 bytes", e.getMessage());
		}
		
		assertEquals(0, bis.available());
	}
	

	public void testBounded_readIntoArray_notExceeded()
		throws Exception {
		
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		
		final int limit = data.length + 1;
		
		BoundedInputStream bis = new BoundedInputStream(stream, limit);
		
		assertEquals(limit, bis.getLimitBytes());
		
		byte[] readData = new byte[data.length];
		
		assertEquals(data.length, bis.read(readData));
		
		assertEquals(0, bis.available());
	}
	

	public void testBounded_readByInt_exceed()
		throws Exception {
		
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		
		final int limit = 50;
		
		BoundedInputStream bis = new BoundedInputStream(stream, limit);
		
		assertEquals(limit, bis.getLimitBytes());
		
		for (int i=0; i<limit; i++) {
			assertTrue(bis.read() == 1);
		}
		
		try {
			bis.read();
			fail();
		} catch (IOException e) {
			assertEquals("Exceeded configured input limit of 50 bytes", e.getMessage());
		}
		
		assertEquals(0, bis.available());
	}
	

	public void testBounded_readByInt_notExceeded()
		throws Exception {
		
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		
		final int limit = data.length + 1;
		
		BoundedInputStream bis = new BoundedInputStream(stream, limit);
		
		assertEquals(limit, bis.getLimitBytes());
		
		for (int i=0; i< limit -1 ; i++) {
			assertTrue(bis.read() == 1);
		}
		assertEquals(-1L, bis.read());
		assertEquals(0, bis.available());
	}
	

	public void testUnbounded_readByInt()
		throws Exception {
		
		byte[] data = createDataArray();
		InputStream stream = new ByteArrayInputStream(data);
		
		BoundedInputStream bis = new BoundedInputStream(stream, -1L);
		
		assertEquals(-1L, bis.getLimitBytes());
		
		for (int i=0; i< data.length ; i++) {
			assertTrue(bis.read() == 1);
		}
		assertEquals(-1L, bis.read());
		assertEquals(0, bis.available());
	}
}
