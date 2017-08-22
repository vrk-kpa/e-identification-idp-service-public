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
package fi.vm.kapa.identification.shibboleth.extattribute;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.security.Principal;

import javax.ws.rs.NotFoundException;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import fi.vm.kapa.identification.shibboleth.client.ProxyClient;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ProfileRequestContext.class)
public class ShibbolethExtAttributeConnectorTest {

    @Test
    public void testProxy404Error() throws Exception {
        Principal principal = mock(Principal.class);
        when(principal.toString()).thenReturn("urn:oid:1.2.3.4.5.6.7");

        ProfileRequestContext baseContext = PowerMockito.mock(ProfileRequestContext.class);
        
        RequestedPrincipalContext requestedPrincipalContext = new RequestedPrincipalContext();
        requestedPrincipalContext.setMatchingPrincipal(principal);

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.addSubcontext(requestedPrincipalContext);
        when(baseContext.getSubcontext(AuthenticationContext.class)).thenReturn(authenticationContext);
        
        AttributeResolutionContext attributeResolutionContext = mock(AttributeResolutionContext.class);
        when(attributeResolutionContext.getParent()).thenReturn(baseContext);
        
        AttributeResolverWorkContext attributeResolverWorkContext = mock(AttributeResolverWorkContext.class);
        
        ShibbolethExtAttributeConnector connector = new ShibbolethExtAttributeConnector();
        connector.setProxySessionMismatchAttribute("testAttribute");
        ShibbolethExtAttributeConnector spy = spy(connector);
        ProxyClient proxyClient = mock(ProxyClient.class);
        when(proxyClient.getSessionAttributes(any(), any(), any(), anyBoolean(), anyString())).thenThrow(new NotFoundException("Test"));
        doReturn(proxyClient).when(spy).getProxyClient();
        
        assertEquals(spy.doDataConnectorResolve(attributeResolutionContext, attributeResolverWorkContext).get("testAttribute").getValues().get(0).getDisplayValue(), "true");
    }

}
