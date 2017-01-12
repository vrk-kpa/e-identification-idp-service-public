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

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;

import org.w3c.dom.Element;

import net.shibboleth.idp.attribute.resolver.spring.dc.impl.AbstractDataConnectorParser;

public class ShibbolethExtAttributeConnectorParser extends AbstractDataConnectorParser {

    public static final QName SCHEMA_NAME = new QName(ShibbolethExtNamespaceHandler.NAMESPACE, "ProxyDataConnector");

    @Override
    protected Class<ShibbolethExtAttributeConnector> getNativeBeanClass() {
        return ShibbolethExtAttributeConnector.class;
    }

    @Override
    protected void doV2Parse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String proxyUrl = element.getAttributeNS(null, "proxyUrl");
        builder.addPropertyValue("proxyUrl", proxyUrl);
        String proxySessionMismatchAttribute = element.getAttributeNS(null, "proxySessionMismatchAttribute");
        builder.addPropertyValue("proxySessionMismatchAttribute", proxySessionMismatchAttribute);
    }
}