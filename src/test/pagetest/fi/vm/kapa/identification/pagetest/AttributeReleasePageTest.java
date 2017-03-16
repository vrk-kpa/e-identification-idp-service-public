/**
 * The MIT License
 * Copyright (c) 2015 Population Register Centre
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fi.vm.kapa.identification.pagetest;

import fi.vm.kapa.identification.pagetest.utils.AttributeRelease;
import fi.vm.kapa.identification.pagetest.utils.VelocityServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AttributeReleasePageTest {

    private Path templateRoot = Paths.get("conf/shibboleth/views/");
    private AttributeRelease attributeRelease = new AttributeRelease(templateRoot);
    private VelocityServer velocityServer = new VelocityServer(9876);

    @Before
    public void setUp() throws Exception {
        velocityServer.setResourceHandler("/idp/profile/SAML2/Redirect/SSO", attributeRelease);
        velocityServer.start();
    }

    @After
    public void tearDown() throws Exception {
        velocityServer.stop();
    }

    @Test
    public void attributeTestPageDoesNotHaveFirstNameWhenNotGiven() throws Exception {
        Map<String,String> personAttributes = new HashMap<>();
        attributeRelease.setPersonAttributes(personAttributes);
        assertFalse(attributeRelease.renderPage().contains("firstName"));
        assertFalse(attributeRelease.renderPage().contains("givenName"));
    }

    @Test
    public void attributeTestPageShowsFirstNames() throws Exception {
        Map<String,String> personAttributes = new HashMap<>();
        personAttributes.put("firstName", "firstName");
        attributeRelease.setPersonAttributes(personAttributes);
        assertTrue(attributeRelease.renderPage().contains("<strong>firstName</strong>"));
    }

    @Test
    public void attributeTestPageShowsGivenNameWhenFirstNameIsNotShown() throws Exception {
        Map<String,String> personAttributes = new HashMap<>();
        personAttributes.put("givenName", "givenName");
        attributeRelease.setPersonAttributes(personAttributes);
        String page = attributeRelease.renderPage();
        assertTrue(page.contains("<strong>givenName</strong>"));
    }

    @Test
    public void attributeTestPageShowsFamilyName() throws Exception {
        Map<String,String> personAttributes = new HashMap<>();
        personAttributes.put("familyName", "familyName");
        attributeRelease.setPersonAttributes(personAttributes);
        assertTrue(attributeRelease.renderPage().contains("<strong>familyName</strong>"));
    }

    @Test
    public void attributeTestPageShowsDateOfBirth() throws Exception {
        Map<String,String> personAttributes = new HashMap<>();
        personAttributes.put("dateOfBirth", "1999-12-31");
        attributeRelease.setPersonAttributes(personAttributes);
        assertTrue(attributeRelease.renderPage().contains("<strong>1999-12-31</strong>"));
    }

}
