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
package fi.vm.kapa.identification.pagetest.utils;

import fi.vm.kapa.identification.pagetest.utils.idp.HtmlEncoderWrapper;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.context.SessionContext;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.messaging.context.BaseContext;

import java.io.StringWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AttributeRelease implements HtmlProducer {

    private final VelocityEngine velocityEngine;
    private Map<String,IdPAttribute> personAttributes = new HashMap<>();
    private Path currentDir = Paths.get("");

    public AttributeRelease(Path templateRoot) {
        velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.FILE_RESOURCE_LOADER_PATH, templateRoot.toString());
        velocityEngine.init();
    }

    public void setPersonAttributes(Map<String,String> personStringAttributes) {
        Map<String,IdPAttribute> attributes = new HashMap<>();
        personStringAttributes.forEach((key, value) -> attributes.put(key, asIdPAttribute(key, value)));
        this.personAttributes = attributes;
    }

    @Override
    public String renderPage() throws ClassNotFoundException {
        Template t = velocityEngine.getTemplate(currentDir.resolve("intercept/attribute-release.vm").toString());
        VelocityContext context = new VelocityContext();
        BaseContext profileRequestContext = mock(BaseContext.class);
        SessionContext sessionContext = mock(SessionContext.class);
        IdPSession idPSession = mock(IdPSession.class);
        when(profileRequestContext.getSubcontext(anyString())).thenReturn(sessionContext);
        when(sessionContext.getIdPSession()).thenReturn(idPSession);

        // net.shibboleth.idp.consent.context.impl.AttributeReleaseContext
        AttributeReleaseContext attributeReleaseContext = mock(AttributeReleaseContext.class);
        when(attributeReleaseContext.getConsentableAttributes()).thenReturn(personAttributes);
        context.put("sessionContext", sessionContext);
        context.put("spCounter", 1);
        context.put("spDisplayNameFi", "TESTI_FI");
        context.put("spDisplayNameSv", "TESTI_SV");
        context.put("spDisplayNameEn", "TESTI_EN");
        context.put("attributeReleaseContext", attributeReleaseContext);
        context.put("encoder", new HtmlEncoderWrapper());
        StringWriter writer = new StringWriter();
        t.merge( context, writer );
        return writer.toString();
    }

    public static void main(String[] args) throws Exception {
        AttributeRelease attributeRelease = new AttributeRelease(Paths.get("."));
        attributeRelease.setPersonAttributes(getDefaultAttributes());
        String page = attributeRelease.renderPage();
        System.out.println(page);
    }

    static Map<String,String> getDefaultAttributes() {
        Map<String,String> attributes = new HashMap<>();
        attributes.put("vtjVerified", "1");

        attributes.put("nationalIdentificationNumber", "HETU_123123");
        attributes.put("electronicIdentificationNumber", "SATU_123123");
        attributes.put("kid", "kid");

        attributes.put("sn", "surname");
        attributes.put("firstName", "firstName");
        attributes.put("givenName", "givenName");
        attributes.put("cn", "common name");
        attributes.put("legacyPersonName", "legacy person name");
        attributes.put("displayName", "displayName");
        attributes.put("telephone", "+358 55 555 5555");

        attributes.put("municipality", "municipality");
        attributes.put("municipalityCode", "municipalityCode");
        attributes.put("domesticAddress", "domesticAddress");
        attributes.put("postalCode", "postalCode");
        attributes.put("city", "city");
        attributes.put("foreignAddress", "foreignAddress");
        attributes.put("foreignLocalityAndState", "foreignLocalityAndState");
        attributes.put("foreignLocalityAndStateClearText", "foreignLocalityAndStateClearText");
        attributes.put("stateCode", "stateCode");
        attributes.put("temporaryPostalCode", "temporaryPostalCode");
        attributes.put("temporaryDomesticAddress", "temporaryDomesticAddress");
        attributes.put("temporaryCity", "temporaryCity");
        attributes.put("finnishCitizenship", "finnishCitizenship");
        attributes.put("personIdentifier", "personIdentifier");

        attributes.put("protectionOrder", "1");
        return attributes;
    }

    private interface AttributeReleaseContext {
        Map<String,IdPAttribute> getConsentableAttributes();
    }

    private static IdPAttribute asIdPAttribute(String attributeId, String attributeValue) {
        IdPAttribute idPAttribute = new IdPAttribute(attributeId);
        IdPAttributeValue<String> stringIdPAttributeValue = new StringAttributeValue(attributeValue);
        idPAttribute.setValues(Arrays.asList(stringIdPAttributeValue));
        return idPAttribute;
    }


}
