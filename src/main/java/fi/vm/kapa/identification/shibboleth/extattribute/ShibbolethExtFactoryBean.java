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

import net.shibboleth.ext.spring.factory.AbstractComponentAwareFactoryBean;

public class ShibbolethExtFactoryBean extends AbstractComponentAwareFactoryBean {

    private String proxyUrl;
    private String proxySessionMismatchAttribute;

    @Override
    public Class getObjectType() {
        return ShibbolethExtAttributeConnector.class;
    }

    @Override
    protected ShibbolethExtAttributeConnector doCreateInstance() throws Exception {
        ShibbolethExtAttributeConnector proxyConnector = new ShibbolethExtAttributeConnector();
        proxyConnector.setProxyUrl(proxyUrl);

        return proxyConnector;
    }

    public String getProxyUrl() {
        return proxyUrl;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public String getProxySessionMismatchAttribute() {
        return proxySessionMismatchAttribute;
    }

    public void setProxySessionMismatchAttribute(String proxySessionMismatchAttribute) {
        this.proxySessionMismatchAttribute = proxySessionMismatchAttribute;
    }
    
}
