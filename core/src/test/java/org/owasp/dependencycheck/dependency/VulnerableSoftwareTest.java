/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import static org.hamcrest.CoreMatchers.is;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 *
 * @author Jeremy Long
 */
public class VulnerableSoftwareTest extends BaseTest {

    /**
     * Test of equals method, of class VulnerableSoftware.
     *
     * @throws CpeValidationException
     */
    @Test
    public void testEquals() throws CpeValidationException {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        VulnerableSoftware obj = null;
        VulnerableSoftware instance = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1").build();
        assertFalse(instance.equals(obj));

        obj = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1.0").build();
        instance = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1").build();
        assertFalse(instance.equals(obj));

        obj = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1.0").build();
        instance = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1.0").build();
        assertTrue(instance.equals(obj));
    }

    /**
     * Test of hashCode method, of class VulnerableSoftware.
     *
     * @throws CpeValidationException
     */
    @Test
    public void testHashCode() throws CpeValidationException {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        VulnerableSoftware instance = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1").build();
        int expResult = 1849413912;
        int result = instance.hashCode();
        assertEquals(expResult, result);
    }

    /**
     * Test of compareTo method, of class VulnerableSoftware.
     * @throws CpeValidationException
     */
    @Test
    public void testCompareTo() throws CpeValidationException {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        VulnerableSoftware obj = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1.0").build();;
        VulnerableSoftware instance = builder.part(Part.APPLICATION).vendor("mortbay").product("jetty").version("6.1").build();
        int result = instance.compareTo(obj);
        assertTrue(result<0);
        
        obj = builder.part(Part.APPLICATION).vendor("yahoo").product("toolbar").version("3.1.0.20130813024103").build();;
        instance = builder.part(Part.APPLICATION).vendor("yahoo").product("toolbar").version("3.1.0.20130813024104").build();;
        result = instance.compareTo(obj);
        assertTrue(result>0);
    }

}
