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

import fi.vm.kapa.identification.dto.SessionAttributeDTO;
import fi.vm.kapa.identification.shibboleth.client.ProxyClient;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractDataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.ws.rs.NotFoundException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ShibbolethExtAttributeConnector extends AbstractDataConnector {

    private final Logger logger = LoggerFactory.getLogger(ShibbolethExtAttributeConnector.class);

    private String proxyUrl;
    private String proxySessionMismatchAttribute;

    @Nullable
    @Override
    protected Map<String, IdPAttribute> doDataConnectorResolve(
            @Nonnull AttributeResolutionContext attributeResolutionContext,
            @Nonnull AttributeResolverWorkContext attributeResolverWorkContext)
            throws ResolutionException {

        String matchingAuthContextClass = null;
        try {
            matchingAuthContextClass = attributeResolutionContext.getParent().getSubcontext(AuthenticationContext.class).getSubcontext(RequestedPrincipalContext.class).getMatchingPrincipal().toString();
        } catch (Exception e) {
            logger.warn("Failed to assign matchingAuthContextClass", e);
            throw new ResolutionException("Failed to assign matchingAuthContextClass", e);
        }
        String authMethodOid;
        if (StringUtils.isNotBlank(matchingAuthContextClass) && StringUtils.isNotBlank(parseOid(matchingAuthContextClass))) {
            authMethodOid = parseOid(matchingAuthContextClass);
            logger.debug("Matching authentication method OID: " + authMethodOid);
        } else {
            logger.warn("Failed to parse authMethodOid");
            throw new ResolutionException("Failed to parse authMethodOid");
        }

        logger.debug("Trying to resolve attributes from Proxy REST URL: " + proxyUrl);
        Map<String, IdPAttribute> attributes = new HashMap<>();
        String uid = attributeResolutionContext.getPrincipal();
        String relyingParty = attributeResolutionContext.getAttributeRecipientID();
        logger.debug("Using uid: '{}', authmethodoid: '{}', relyingparty: '{}' to fetch session attributes", uid, authMethodOid, relyingParty);
        try {
            SessionAttributeDTO attributeResponse = getProxyClient().getSessionAttributes(uid, authMethodOid, relyingParty);
            Map<String, String> attributeMap = attributeResponse.getAttributeMap();
            logger.debug("Attribute map size: {}", attributeMap.size());
            attributeMap.keySet().forEach(key -> {
                final String value = attributeMap.get(key);
                logger.debug("--attribute key: {}, attribute value: {}", key, value);
                if (StringUtils.isNotBlank(value)) {
                    IdPAttribute idPAttribute = new IdPAttribute(key);
                    List<IdPAttributeValue<String>> values = new ArrayList<>();
                    values.add(new StringAttributeValue(value));
                    idPAttribute.setValues(values);
                    attributes.put(key, idPAttribute);
                }
            });
        } catch ( NotFoundException ne ){
            logger.warn(proxySessionMismatchAttribute  + " error: ", ne);
            IdPAttribute idPAttribute = new IdPAttribute(proxySessionMismatchAttribute);
            List<IdPAttributeValue<String>> values = new ArrayList<>();
            values.add(new StringAttributeValue("true"));
            idPAttribute.setValues(values);
            attributes.put(proxySessionMismatchAttribute, idPAttribute);
            return attributes;
        } catch (Exception e) {
            logger.warn("Failed to resolve attributes", e);
            throw new ResolutionException("Failed to resolve attributes");
        }

        return attributes;
    }

    public ProxyClient getProxyClient() {

        return new ProxyClient(proxyUrl);
    }
    
    public void setProxySessionMismatchAttribute(String proxySessionMismatchAttribute) {
        this.proxySessionMismatchAttribute = proxySessionMismatchAttribute;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    private String parseOid(String authContextClass) {
        Pattern oid = Pattern.compile("urn:oid:(?:\\d+\\.)+\\d+");
        Matcher matcher = oid.matcher(authContextClass);
        if (matcher.find()) {
            return matcher.group(0);
        }
        return null;
    }
}
