package fi.vm.kapa.identification.pagetest.utils; /**
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
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import fi.vm.kapa.identification.pagetest.utils.idp.HtmlEncoderWrapper;
import net.shibboleth.idp.saml.session.SAML2SPSession;
import net.shibboleth.idp.session.SPSession;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;

import java.io.StringWriter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LogoutPropagate implements HtmlProducer {

    private final VelocityEngine velocityEngine;

    public LogoutPropagate() {
        velocityEngine = new VelocityEngine();
        velocityEngine.init();
    }

    public Multimap<String,SPSession> getSessionMap() {
        Multimap<String,SPSession> sessionMap = ArrayListMultimap.create();
        sessionMap.put("key", new SAML2SPSession("123", 10L, 10000L, new NameIDBuilder().buildObject("uri", "localname", "ns-prefix"), "assertedIndex"));
        return sessionMap;
    }

    @Override
    public String renderPage() throws ClassNotFoundException {
        Template t = velocityEngine.getTemplate("logout-propagate.vm");
        VelocityContext context = new VelocityContext();
        context.put("spDisplayNameFi", "TESTI_FI");
        context.put("encoder", new HtmlEncoderWrapper());

        MockLogoutContext mockLogoutContext = mock(MockLogoutContext.class);
        when(mockLogoutContext.getSessionMap()).thenReturn(getSessionMap());
        context.put("logoutContext", mockLogoutContext);
        context.put("htmlEncoder", new HtmlEncoderWrapper());
        StringWriter writer = new StringWriter();
        t.merge(context, writer);
        return writer.toString();
    }


    public interface MockLogoutContext {
        Multimap<String,SPSession> getSessionMap();
    }
}
