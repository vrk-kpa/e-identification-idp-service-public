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
package fi.vm.kapa.identification.shibboleth.client;

import fi.vm.kapa.identification.dto.ProxyMessageDTO;
import fi.vm.kapa.identification.dto.SessionAttributeDTO;
import fi.vm.kapa.identification.resource.ProxyResource;
import org.glassfish.jersey.client.proxy.WebResourceFactory;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

public class ProxyClient {

    private final static Logger logger = LoggerFactory.getLogger(ProxyClient.class);

    private ProxyResource proxyResource;

    public ProxyClient(String proxyURI) {
        Client client = ClientBuilder.newClient()
            .register(JacksonFeature.class);
        WebTarget target = client.target(proxyURI);
        this.proxyResource = WebResourceFactory.newResource(ProxyResource.class, target);
    }

    public ProxyMessageDTO addSession(String relyingParty,
                                      String entityId,
                                      String countryCode,
                                      String uid,
                                      String key,
                                      String authMethodReqStr,
                                      String logTag) {
        logger.debug("Add new session - relying party: {}, entityId: {}, countryCode: {}, uid: {}, conversation key: {}, authentication methods: {}, tag: {}", relyingParty, entityId, countryCode, uid, key, authMethodReqStr, logTag);
        return proxyResource.fromIdPInitSession(relyingParty, entityId, countryCode, uid, key, authMethodReqStr, logTag);
    }

    public ProxyMessageDTO getSessionByTokenId(String tokenId, String phaseId, String logTag) {
        logger.debug("Fetch session by token ID - token ID: {}, phase ID: {}, tag: {}", tokenId, phaseId, logTag);
        return proxyResource.fromIdPRequestSession(tokenId, phaseId, logTag);
    }

    public ProxyMessageDTO purgeSession(String tokenId, String phaseId, String logTag) {
        logger.debug("Purge session - tid: {}, pid: {}, tag: {}", tokenId, phaseId, logTag);
        return proxyResource.fromIdPPurgeSession(tokenId, phaseId, logTag);
    }

    public SessionAttributeDTO getSessionAttributes(String uid, String authMethodOid, String relyingParty, boolean tokenRequired, String authnRequestId) {
        logger.debug("Fetch session attributes - uid: {}, authentication method: {}, relying party: {}, tokenRequired: {}, authnRequestId: {}", uid, authMethodOid, relyingParty, tokenRequired, authnRequestId);
        return proxyResource.getSessionAttributes(uid, authMethodOid, relyingParty, tokenRequired, authnRequestId);
    }
}
