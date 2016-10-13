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


import junit.framework.TestCase;


public class ContainerTest extends TestCase {
	

	public void testDefaultConstructor() {
		
		Container<String> container = new Container<>();
		assertNull(container.get());
	}
	
	
	public void testParamConstructor() {
		
		Container<String> container = new Container<>("abc");
		assertEquals("abc", container.get());
	}
	
	
	public void testGetAndSet() {
		
		Container<String> container = new Container<>();
		container.set("abc");
		assertEquals("abc", container.get());
		container.set(null);
		assertNull(container.get());
	}
	
	
	public void testMutable() {
		
		Container<String> container = new Container<>("abc");
		assertEquals("abc", container.get());
		container.set("def");
		assertEquals("def", container.get());
	}
}
