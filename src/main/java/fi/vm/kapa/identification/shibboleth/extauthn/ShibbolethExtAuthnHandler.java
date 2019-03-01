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
package fi.vm.kapa.identification.shibboleth.extauthn;

import fi.vm.kapa.identification.dto.ProxyMessageDTO;
import fi.vm.kapa.identification.service.PhaseIdHistoryService;
import fi.vm.kapa.identification.service.PhaseIdService;
import fi.vm.kapa.identification.service.UrlParamService;
import fi.vm.kapa.identification.shibboleth.client.ProxyClient;
import fi.vm.kapa.identification.shibboleth.exception.SessionFinaliseException;
import fi.vm.kapa.identification.type.AuthMethod;
import fi.vm.kapa.identification.type.SessionStatus;
import fi.vm.kapa.identification.util.AuthMethodHelper;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.idp.session.context.SessionContext;
import org.apache.commons.lang.StringUtils;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@WebServlet(name = "ShibbolethExtAuthnHandler", urlPatterns = {"/authn/External/*"})
public class ShibbolethExtAuthnHandler extends HttpServlet {

    private final static Logger logger = LoggerFactory.getLogger(ShibbolethExtAuthnHandler.class);
    private final static String LANG_COOKIE_NAME = "E-Identification-Lang";
    private final static String DEFAULT_LANG = "fi";

    private String sharedSecret;
    private String hmacAlgorithm;
    private int timeIntervalBuilt;
    private int timeIntervalInit;
    private int timeIntervalAuth;
    private PhaseIdHistoryService historyService;
    private String spSecuredURLBase;
    private String defaultErrorBase;
    private String stepSessionInit;
    private String stepRedirectFromSP;
    private String stepGetSession;
    private String stepCancel;
    private String discoveryPagePath;
    private String spRedirectBasePath;
    private String timeoutPagePath;
    private String proxyUrl;
    private String stepDiscoveryPage;

    /* These strings define the error redirect URL query parameter that can be
     * used to guide the error page, the value matches the property key that
     * fetches the correct language variant for the error message
     */
    private String errorParamIdpExt;
    private String errorParamInternal;
    private String errorParamInvalidEID;
    private String errorParamPhaseID;
    private String errorParamPhaseIDDisco;
    private String errorParamCancel;

    public void init(ServletConfig config) throws ServletException {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("/opt/identity-provider/identity-provider.properties"));
            spSecuredURLBase = props.getProperty("sp.redirect.url");
            discoveryPagePath = props.getProperty("discovery.page.path");
            spRedirectBasePath = props.getProperty("sp.redirect.base.path");
            timeoutPagePath = "/timeout";
            defaultErrorBase = props.getProperty("default.error.url");
            stepDiscoveryPage = props.getProperty("phase.id.step.zero");
            stepSessionInit = props.getProperty("phase.id.step.one");
            stepRedirectFromSP = props.getProperty("phase.id.step.three");
            stepGetSession = props.getProperty("phase.id.step.four");
            stepCancel = props.getProperty("phase.id.step.five");
            errorParamInternal = props.getProperty("failure.param.internal");
            errorParamIdpExt = props.getProperty("failure.param.idp.ext");
            errorParamInvalidEID = props.getProperty("failure.param.entityid");
            errorParamPhaseID = props.getProperty("failure.param.phaseid");
            errorParamPhaseIDDisco = props.getProperty("failure.param.phaseid.disco");
            errorParamCancel = props.getProperty("failure.param.cancel");
            timeIntervalBuilt = Integer.parseInt(props.getProperty("phase.id.time.built.interval"));
            timeIntervalInit = Integer.parseInt(props.getProperty("phase.id.time.init.interval"));
            timeIntervalAuth = Integer.parseInt(props.getProperty("phase.id.time.auth.interval"));
            sharedSecret = props.getProperty("phase.id.shared.secret");
            hmacAlgorithm = props.getProperty("phase.id.algorithm");
            historyService = PhaseIdHistoryService.getInstance();
            proxyUrl = props.getProperty("proxy.url");
        } catch (Exception e) {
            logger.error("Error initializing ShibbolethExtAuthnHandler", e);
        }    
    }


    /**
     * This method executes the identity building process in two parts. Depending on whether
     * a session already exists, it either initialises a new Proxy session or activates a
     * re-authentication. This is followed by a redirect to the discovery page.
     * After the session has been processed, the session fetch request is parsed.
     * The whole process is made up of seven distinct steps.
     *
     * 1. The IdP redirects here to initialize the external authentication process.
     * 2. The proxy is called with the Shibboleth provided conversation key and uid if IdP session exists.
     * 3. The user is then redirected to the SP to complete external authentication.
     * 4. Once the external authentication succeeds, the SP redirects here with the token ID (tid)
     * and phase ID (pid) request parameters.
     * 5. Check phase ID before doing any processing (pid).
     * 6. Fetch session data from proxy with given tid and pid
     * 7. Finish by calling Shibboleth IdP again with the given remote user uid.
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // Proxy-generated token ID that must be checked first
        String tid = request.getParameter("tid");
        String pid = request.getParameter("pid");
        String status = request.getParameter("status");
        String entityId = request.getParameter("entityId");
        String logTag = request.getParameter("tag");
        String countryCode = request.getParameter("countryCode");
        try { 
            /**
             * Status query parameter is present
             * possible statuses: cancel, timeout, returnFromIdp, return
             */
            if (!StringUtils.isBlank(status)) {
                handleStatus(status, tid, pid, logTag, response, request);
                return;
            }
            /**
             * If token ID is empty, this is an initial call from IdP 
             */
            else if (StringUtils.isBlank(tid)) {
                initializeDiscoSessionAndRedirect(logTag, response, request);
                return;
            } 
            /**
             * If entityId or countryCode is present, this is a return from discovery page after the user has selected authentication method
             */
            else if (!StringUtils.isBlank(entityId) || !StringUtils.isBlank(countryCode)) {
                if (!StringUtils.isBlank(entityId)) {
                    entityId = URLDecoder.decode(entityId, "UTF-8");
                }
                if (!StringUtils.isBlank(countryCode) && !countryCode.matches("^[A-Z]{2}$")) {
                    logger.warn("Invalid countryCode");
                    throw new ExternalAuthenticationException("Invalid countryCode");
                }
                initializeSPSessionAndRedirect(entityId, tid, pid, logTag, countryCode, response, request);
                return;
            }
            /**
             * Token ID is not empty and none of the above apply, this is a return from a successful authentication by the user
             */
            else {
                finalizeSessionAndFinishAuthentication(tid, pid, logTag, response, request);
                return;
            }
        } catch (ExternalAuthenticationException eae) {
            logger.warn("Failure in external authentication", eae);
            response.sendRedirect(createErrorURL(createLogTag(), errorParamIdpExt));

        }
        //We should never get here so just redirect to internal error
        response.sendRedirect(createErrorURL(logTag, errorParamInternal));
    }

    private void finalizeSessionAndFinishAuthentication(
            String tid,
            String pid,
            String logTag,
            HttpServletResponse response,
            HttpServletRequest request) throws ExternalAuthenticationException, IOException {


        ProxyMessageDTO message;
        try {
            message = finalizeSession(tid, pid, logTag);
        } catch (SessionFinaliseException sfe) {
            logger.warn("<<{}>> {}", logTag, sfe.getMessage());
            response.sendRedirect(createErrorURL(logTag, sfe.getErrorCode()));
            return;
        }
        //Get existing active authentication class principals from IdP session
        ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(message.getConversationKey(), request);
        Set<Principal> principals = getExistingActiveAuthenticationClassPrincipals(prc);
        logger.debug("Existing principals in principal set: " + !principals.isEmpty());
        principals.add(new UsernamePrincipal(message.getUid()));
        for (AuthMethod authMethod : message.getSessionAuthenticationMethods()) {
            principals.add(new AuthnContextClassRefPrincipal(authMethod.getOidValue()));
            logger.debug("Added AuthnContextClassRefPrincipal: " + authMethod.getOidValue());
        }
        Subject subject = new Subject();
        subject.getPrincipals().addAll(principals);
        request.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
        ExternalAuthentication.finishExternalAuthentication(message.getConversationKey(), request, response);

    }
    private void initializeDiscoSessionAndRedirect(
            String logTag,
            HttpServletResponse response,
            HttpServletRequest request) throws ExternalAuthenticationException, IOException {
        
                        /**
                 * Get conversation key from Shibboleth IdP (2.)
                 */
                String convKey = ExternalAuthentication.startExternalAuthentication(request);
                /* The above method enriches the servlet request with Shibboleth IdP related
                 * data such as the relying party value which is fetched in the code below.
                 * Note that this data is not fetched from browser generated request but directly
                 * from Shibboleth through internal class method call
                 */
                //Get SP entityID
                String relyingParty = String.valueOf(request.getAttribute(ExternalAuthentication.RELYING_PARTY_PARAM));
                logger.debug("Relying party is: " + relyingParty);

                ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(convKey, request);

                String language = resolveRequestLanguage(prc, request);
                logger.debug("Language is: " + language);
                setLangCookie(request, response, language);

                logIfAuthnMethodsRequested(prc);
                String requestedAuthenticationMethodSetString = getExpandedAuthMethodString(prc);
                //Get existing uid from IdP session. Set value to 0 (AuthMethod INIT) if null.
                String uid = existingAuthenticationSubjectName(prc);
                if (StringUtils.isBlank(uid)) {
                    uid = SessionStatus.INIT.getStatusAsNumericalString(); //"0"
                }
                PhaseIdService phaseIdInitSession;
                try {
                    phaseIdInitSession = new PhaseIdService(sharedSecret, timeIntervalInit, hmacAlgorithm);
                } catch (Exception e) {
                    logger.warn("Failed to initialize new phaseIdInitSession ", e);
                    throw new ExternalAuthenticationException();
                }

                String tokenId = phaseIdInitSession.nextTokenId();
                String phaseId = phaseIdInitSession.newPhaseId(tokenId, stepDiscoveryPage);
                logger.debug("Existing session uid: " + uid);
                if (StringUtils.isBlank(logTag)) {
                    logTag = createLogTag();
                }
                String redirectUrl = createDiscoveryPageUrl(relyingParty, tokenId, phaseId, logTag, requestedAuthenticationMethodSetString, convKey);
                logger.debug("(Initial redirectUrl to SP:  " + redirectUrl);
                response.sendRedirect(redirectUrl);
    }

    private String getExpandedAuthMethodString(ProfileRequestContext prc) {
        String requestedAuthenticationMethodSetString;
        requestedAuthenticationMethodSetString = resolveRequestAuthenticationContextClassList(prc);

        Set<AuthMethod> requestedAuthMethodSet = AuthMethodHelper.getAuthMethodSet(requestedAuthenticationMethodSetString);
        // fLoA2 request must also contain fLoA3 methods
        if ( requestedAuthMethodSet.contains(AuthMethod.fLoA2) ) {
            requestedAuthMethodSet.add(AuthMethod.fLoA3);
        }
        requestedAuthenticationMethodSetString = AuthMethodHelper.getAuthMethodSetAsString(requestedAuthMethodSet);
        return requestedAuthenticationMethodSetString;
    }


    private void initializeSPSessionAndRedirect(
            String entityId,
            String tid,
            String pid,
            String logTag,
            String countryCode,
            HttpServletResponse response,
            HttpServletRequest request) throws ExternalAuthenticationException, IOException {
        
        //PID reuse check is skipped here on purpose to enable browser back-button
        if (validatePhaseId(tid, pid, logTag, stepDiscoveryPage, timeIntervalInit)) {
            ProxyClient proxyClient = new ProxyClient(proxyUrl);
            String convKey = ExternalAuthentication.startExternalAuthentication(request);
            String relyingParty = String.valueOf(request.getAttribute(ExternalAuthentication.RELYING_PARTY_PARAM));
            ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(convKey, request);
            String language = resolveRequestLanguage(prc, request);
            setLangCookie(request, response, language);
            String requestedAuthenticationMethodSet = getExpandedAuthMethodString(prc);
            //Get existing uid from IdP session. Set value to 0 (AuthMethod INIT) if null.
            String uid = existingAuthenticationSubjectName(prc);
            if (StringUtils.isBlank(uid)) {
                uid = SessionStatus.INIT.getStatusAsNumericalString(); //"0"
            }
            response.sendRedirect(initializeSession(request, proxyClient, uid, convKey, relyingParty, requestedAuthenticationMethodSet, entityId, countryCode, language, logTag));
        } else {
            response.sendRedirect(createErrorURL(logTag, errorParamPhaseIDDisco));
        }
    }

    private void handleStatus(
            String status,
            String tid,
            String pid,
            String logTag,
            HttpServletResponse response,
            HttpServletRequest request) throws ExternalAuthenticationException, IOException {

        PhaseIdService phaseIdInitSession;
        PhaseIdService phaseIdBuiltSession;
        switch (status) {
            //Returning from idp by user cancel. Need to purge old session.
            case "returnFromIdp": {                
                if (validatePhaseId(tid, pid, logTag, stepSessionInit, timeIntervalAuth)) {
                    try {
                        ProxyClient proxyClient = new ProxyClient(proxyUrl);
                        phaseIdInitSession = new PhaseIdService(sharedSecret, timeIntervalAuth, hmacAlgorithm);
                        phaseIdBuiltSession = new PhaseIdService(sharedSecret, timeIntervalBuilt, hmacAlgorithm);
                        purgeSession(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag);
                        initializeDiscoSessionAndRedirect(logTag,response,request);
                        return;
                    } catch (Exception ex) {
                        logger.warn("Failed to initialize new phaseIdInitSession ", ex);
                        throw new ExternalAuthenticationException();
                    }
                } else {
                    response.sendRedirect(createErrorURL(logTag, errorParamPhaseID));
                    return;
                }
            }
            //authentication cancelled on discovery page
            case "cancel": {
                if (validatePhaseId(tid, pid, logTag, stepDiscoveryPage, timeIntervalInit)) {
                    // send authn failed SAML response
                    try {
                        cancel(request, response);
                        return;
                    } catch (Exception e) {
                        logger.warn("<<{}>> Failed to purge session", logTag);
                        response.sendRedirect(createErrorURL(logTag, errorParamCancel));
                        return;
                    }
                } else {
                    response.sendRedirect(createErrorURL(logTag, errorParamPhaseID));
                    return;
                }

            }
            // return to original service provider from timeout page
            // send authentication error SAML response
            case "return": {
                String key = request.getParameter("conversation");
                try {
                    returnToService(key, request, response);
                    return;
                } catch (Exception e) {
                    logger.warn("<<{}>> Failed to return to service: {}", logTag, e.getMessage());
                    response.sendRedirect(createErrorURL(logTag, errorParamIdpExt));
                    return;
                }
            }
            // session timed out on disco page
            // purge session and redirect to timeout page
            case "timeout": {
                ProxyClient proxyClient = new ProxyClient(proxyUrl);
                try {
                    phaseIdInitSession = new PhaseIdService(sharedSecret, timeIntervalInit, hmacAlgorithm);
                    phaseIdBuiltSession = new PhaseIdService(sharedSecret, timeIntervalBuilt, hmacAlgorithm);
                } catch (Exception e) {
                    logger.warn("Failed to initialize new phaseIdBuiltSession ", e);
                    throw new ExternalAuthenticationException();
                }
                response.sendRedirect(timeout(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag, request.getParameter("conversation")));
                return;
            }
            //There is something wrong with status query parameter.
            default: {
                response.sendRedirect(createErrorURL(logTag, errorParamInternal));
            }
        }
    }

    private boolean validatePhaseId(String tid, String pid, String logTag, String step, int timeInterval) throws ExternalAuthenticationException {
        PhaseIdService phaseIdInitSession;
        // add ids to history
        historyService.areIdsConsumed(tid, pid);
        try {
            phaseIdInitSession = new PhaseIdService(sharedSecret, timeInterval, hmacAlgorithm);
        } catch (Exception e) {
            logger.warn("Failed to initialize new phaseIdInitSession ", e);
            throw new ExternalAuthenticationException();
        }
        try {
            if (phaseIdInitSession.validateTidAndPid(tid, pid)
                    && phaseIdInitSession.verifyPhaseId(pid, tid, step)) {
                return true;

            } else {
                logger.warn("<<{}>> Failed to verify phase ID", logTag);
                return false;
            }
        } catch (Exception e) {
            logger.warn("<<{}>> Failed to verify phase ID", logTag);
            return false;
        }
    }
    
    /**
     * This log tag is used to track possible errors in log files, this tag must be
     * added to each REST request between servers, it helps to solve possible errors
     * and it must be handled in each server in their error logs, the tag will be
     * e.g. '1503181352a5fc' so that there's at least some information about the
     * time when the error occurred along with unique identifier
     */
    private String createLogTag() {
        SimpleDateFormat date = new SimpleDateFormat("yyMMddHHmm");
        return date.format(new Date()) + new BigInteger(16, new SecureRandom()).toString(16);
    }

    private void cancel(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String key = request.getParameter(ExternalAuthentication.CONVERSATION_KEY);
        logger.debug("Canceling authentication from Shibboleth IdP with conversation key {}", key);
        request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "User canceled authentication");
        ExternalAuthentication.finishExternalAuthentication(key, request, response);
    }

    private String timeout(ProxyClient proxyClient, String tid, String pid, PhaseIdService phaseIdInitSession,
                           PhaseIdService phaseIdBuiltSession, String logTag, String conversionkey) {
        String redirectUrl;
        try {
            purgeSession(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag);
            redirectUrl = timeoutPagePath + "?conversation=" + conversionkey;
        } catch (Exception e) {
            logger.warn("<<{}>> Failed to purge session", logTag);
            redirectUrl = createErrorURL(logTag, errorParamCancel);
        }
        return redirectUrl;
    }

    private void returnToService(String key, HttpServletRequest request,
                                 HttpServletResponse response) throws Exception {
        logger.debug("Returning to service provider with an erroneous SAML message, conversation key {}", key);
        request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "User canceled authentication");
        ExternalAuthentication.finishExternalAuthentication(key, request, response);
    }

    private String initializeSession(HttpServletRequest request,
                                     ProxyClient proxyClient,
                                     String uid, String convKey,
                                     String relyingParty,
                                     String requestedAuthenticationMethodStr,
                                     String entityId,
                                     String countryCode,
                                     String lang,
                                     String logTag) {

        String redirectUrl;
        // Relying party parameter must match the allowed entity ID format
        if (UrlParamService.isValidEntityId(relyingParty)) {
            String spCallUrl = proxySessionInit(request, proxyClient, uid, relyingParty, convKey, logTag, requestedAuthenticationMethodStr, entityId, lang, countryCode);
            if (StringUtils.isNotBlank(spCallUrl)) {
                logger.debug("Session init OK, redirect to SP (3.)  - spCallUrl: {}", spCallUrl);
                /** Session init OK, redirect to SP (3.) */
                redirectUrl = spCallUrl;
            } else {
                logger.warn("<<{}>> Session init failed", logTag);
                redirectUrl = createErrorURL(logTag, errorParamInternal);
            }
        } else {
            logger.error("<<{}>> Received invalid relying party", logTag);
            redirectUrl = createErrorURL(logTag, errorParamInvalidEID);
        }
        return redirectUrl;
    }

    private ProxyMessageDTO finalizeSession(
                                   String tid, String pid,
                                   String logTag) throws SessionFinaliseException, ExternalAuthenticationException {
        String phaseId = null;
        /* Token and phase IDs must be checked if they've been used already
         * in order to prevent replay attacks, there's only a small history
         * that needs to be checked so that performance isn't penalized
         */
        if (!historyService.areIdsConsumed(tid, pid)) {
            try {
                /** Phase ID must be checked and new must be generated for Proxy (5.) */
                /* Both token ID and phase ID values must always match to a given set of rules
                 * since these values are exposed to public, they could have been tampered
                 */
                PhaseIdService phaseIdBuiltSession = new PhaseIdService(sharedSecret, timeIntervalBuilt, hmacAlgorithm);
                if (phaseIdBuiltSession.validateTidAndPid(tid, pid) &&
                    phaseIdBuiltSession.verifyPhaseId(pid, tid, stepRedirectFromSP)) {                    
                    phaseId = phaseIdBuiltSession.newPhaseId(tid, stepGetSession);
                }
            } catch (Exception e) {
                throw new SessionFinaliseException("Failed to verify or generate next phase ID", errorParamPhaseID);
            }
        } else {
            logger.warn("Received already consumed token and phase IDs!!");
        }
        if (phaseId == null) {
            throw new SessionFinaliseException("Phase ID is not valid", errorParamPhaseID);
        }
        /** Fetch session data from Proxy (6.) */
        ProxyClient proxyClient = new ProxyClient(proxyUrl);
        ProxyMessageDTO message = sessionFetch(proxyClient, tid, phaseId, logTag);
        String conversationKey = message.getConversationKey();
        String uid = message.getUid();
        AuthMethod[] authMethods = message.getSessionAuthenticationMethods();

        logger.debug("--conversationKey: " + conversationKey + ", uid: " + uid + ", used auth method: " + (authMethods == null ? "null" : authMethods[0]));
        // This array is always fixed in length and it must be kept that way
        if (StringUtils.isBlank(conversationKey) || StringUtils.isBlank(uid) || authMethods == null || authMethods.length == 0 ) {
            throw new SessionFinaliseException("Getting session identifiers failed", errorParamPhaseID);
        }

        return message;
    }
    
    /**
     * Purges a session from session cache at Proxy
     * @param proxyClient
     * @param tid
     * @param pid
     * @param phaseIdInitSession
     * @param phaseIdBuiltSession
     * @param logTag
     * @return Session conversation key
     * @throws Exception
     */
    private String purgeSession(ProxyClient proxyClient, String tid, String pid, PhaseIdService phaseIdInitSession, PhaseIdService phaseIdBuiltSession, String logTag) throws Exception {
        logger.debug("<<{}>> Purging session", logTag);
        String cancelPhaseId = null;
        ProxyMessageDTO proxyMessage;
        
        if (phaseIdInitSession.validateTidAndPid(tid, pid) &&
            phaseIdInitSession.verifyPhaseId(pid, tid, stepSessionInit) ||
            phaseIdInitSession.verifyPhaseId(pid, tid, stepDiscoveryPage)) {
            cancelPhaseId = phaseIdBuiltSession.newPhaseId(tid, stepCancel);
        }
        if (cancelPhaseId != null) {
            proxyMessage = proxyClient.purgeSession(tid, cancelPhaseId, logTag);
        } else {
            logger.warn("<<{}>> Phase and token id validation failed when purging session", logTag);
            throw new Exception();
        }
        return proxyMessage.getConversationKey();
    }

    /**
     * Calls proxy component to initialise a new session
     * or re-authenticate an existing session
     * and constructs discovery page URL.
     *
     * @param proxyClient
     * @param uid
     * @param relyingParty
     * @param conversationKey
     * @param logTag
     * @param requestedAuthenticationMethodSet
     * @return
     */

    private String proxySessionInit(HttpServletRequest request,
                               ProxyClient proxyClient,
                               String uid,
                               String relyingParty,
                               String conversationKey,
                               String logTag,
                               final String requestedAuthenticationMethodSet,
                               String entityId,
                               String lang, 
                               String countryCode) {

        String spRedirectUrl = null;

        ProxyMessageDTO responseEntity = proxyClient.addSession(relyingParty, entityId, countryCode, uid, conversationKey, requestedAuthenticationMethodSet, logTag);

        if (responseEntity != null) {
            try {
                /**
                 * generating a redirect link to requested idp
                 */
                spRedirectUrl = spRedirectBasePath;
                String countryCodeUrlParam = "";
                spRedirectUrl += responseEntity.getLoginContext();
                
                if (StringUtils.isEmpty(countryCode)) {                                      
                    spRedirectUrl += "/" + lang;
                } else {                    
                    countryCodeUrlParam = "&countryCode=" + countryCode;
                }
                spRedirectUrl += "?SAMLDS=1" + countryCodeUrlParam + "&target=";
                spRedirectUrl += java.net.URLEncoder.encode(spSecuredURLBase
                        + responseEntity.getTokenId()
                        + "&pid=" + responseEntity.getPhaseId()
                        + "&tag=" + logTag + "&conversation="
                        + conversationKey, 
                        StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException ex) {
                logger.warn("<<{}>> Failed to create spRedirectUrl ", logTag, ex);
            }
        }

        return spRedirectUrl;
    }
 
    private String createDiscoveryPageUrl(String relyingParty,
                                    String tid, String pid,
                                    String logTag, 
                                    final String requestedAuthenticationMethodSet, 
                                    String conversationKey ) {
        String discoveryPageUrl = null;
        try {

            discoveryPageUrl = discoveryPagePath + "?entityId=" + java.net.URLEncoder.encode(relyingParty, StandardCharsets.UTF_8.toString());
            discoveryPageUrl = discoveryPageUrl + "&timeout=" + getDiscoveryPageTimeout();
            discoveryPageUrl = discoveryPageUrl + "&tid=" + tid + "&pid=" + pid + "&tag=" + logTag;
            discoveryPageUrl = discoveryPageUrl + "&authMethdReq=" + requestedAuthenticationMethodSet;
            discoveryPageUrl = discoveryPageUrl + "&conversation=" + conversationKey;
        } catch (IOException ioe) {
            logger.warn("<<{}>> Failed to create spCallUrl ", logTag, ioe);
        }
        return discoveryPageUrl;
    }

    private ProxyMessageDTO sessionFetch(ProxyClient proxyClient, String tokenId, String phaseId, String logTag) {
        return proxyClient.getSessionByTokenId(tokenId, phaseId, logTag);
    }

    private String createErrorURL(String logTag, String message) {
        return defaultErrorBase + "?t=" + logTag + "&m=" + message;
    }

    /**
     * Resolve language based on the following priority: request context, cookie, default value
     *
     * @param profileRequestContext Shibboleth request context
     * @param request               HTTP request containing possible language cookie
     * @return language parameter form message
     */
    private String resolveRequestLanguage(ProfileRequestContext profileRequestContext, HttpServletRequest request) {
        AuthnRequest message = (AuthnRequest) profileRequestContext.getInboundMessageContext().getMessage();
        Extensions extensions = message.getExtensions();
        String langFromCookie = null, resolvedLang;
        if (getCookie(request, LANG_COOKIE_NAME) != null) {
            langFromCookie = getCookie(request, LANG_COOKIE_NAME).getValue();
        }
        if (extensions != null) {
            // look for vetuma-style language parameter for backward compatibility
            String vetumaLang = extensions.getOrderedChildren()
                .stream()
                .filter(extension -> extension.getElementQName().getLocalPart().equals("vetuma"))
                .findFirst()
                .flatMap(vetumaNode -> vetumaNode.getOrderedChildren()
                    .stream()
                    .filter(lgNode -> lgNode.getElementQName().getLocalPart().equals("LG"))
                    .findFirst())
                .map(langNode -> langNode.getDOM().getFirstChild().getNodeValue())
                .orElse(langFromCookie);

            logger.debug("Resolved vetuma-style language parameter from authentication request - " + vetumaLang);
            resolvedLang = vetumaLang;
        } else {
            logger.debug("Resolved language parameter from cookie - " + langFromCookie);
            resolvedLang = langFromCookie;
        }
        if (StringUtils.isBlank(resolvedLang) || !resolvedLang.matches("fi|sv|en")) {
            logger.debug("Could not find valid language parameter in authentication request, using default language - " + DEFAULT_LANG);
            return DEFAULT_LANG;
        }
        return resolvedLang;
    }


    /**
     * Logs if service provider explicitly requested authentication methods in SAML authn request.
     *
     * @param profileRequestContext     Shibboleth request context
     */
    private void logIfAuthnMethodsRequested(ProfileRequestContext profileRequestContext) {

        AuthnRequest message = (AuthnRequest) profileRequestContext.getInboundMessageContext().getMessage();
        if( message.getRequestedAuthnContext() != null) {

            List<AuthnContextClassRef> authnContextClassRefs = message.getRequestedAuthnContext().getAuthnContextClassRefs();
            if( !CollectionUtils.isEmpty(authnContextClassRefs) ) {
                logger.info("Service provider explicitly requested authentication methods; " +
                                "Service provider: {}, authentication methods: {}.",
                        message.getIssuer().getValue(),
                        (authnContextClassRefs.stream()
                                .map(authnContextClassRef -> authnContextClassRef.getAuthnContextClassRef()))
                                .collect(Collectors.toList()));
            }
        }

    }


    /**
     * Set a browser language cookie based on authentication request language parameter.
     * Set correct security parameters.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @param lang     Language
     */
    private void setLangCookie(HttpServletRequest request, HttpServletResponse response, String lang) {
        Cookie langCookie = getCookie(request, LANG_COOKIE_NAME);
        if (langCookie == null) {
            langCookie = new Cookie(LANG_COOKIE_NAME, DEFAULT_LANG);
        }
        langCookie.setValue(lang);
        langCookie.setPath("/");
        langCookie.setSecure(true);
        response.addCookie(langCookie);
    }

    /**
     * Return request cookie by name
     *
     * @param request    HTTP request
     * @param cookieName Cookie name
     * @return existing request cookie
     */
    private Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Find out userPrincipal name (uid) of existing session.
     * This is the common session identifier shared by IdP and Proxy.
     *
     * @param profileRequestContext     Shibboleth request context
     * @return userPrincipal            name of existing session
     */
    private String existingAuthenticationSubjectName(ProfileRequestContext profileRequestContext) {
        SessionContext session = profileRequestContext.getSubcontext(SessionContext.class);
        if (session != null) {
            return session.getIdPSession().getPrincipalName();
        }
        return null;
    }

    /**
     * Find out existing active authentication principals for IdP session.
     *
     * @param profileRequestContext     a ProfileRequestContext
     * @return set of active authentication class principals
     */
    private Set<Principal> getExistingActiveAuthenticationClassPrincipals(ProfileRequestContext profileRequestContext) {
        Set<Principal> existingAuthenticationClassPrincipals = new HashSet<>();
        AuthenticationContext ac = profileRequestContext.getSubcontext(AuthenticationContext.class);
        Map<String,AuthenticationResult> activeResults = ac.getActiveResults();
        if (activeResults == null || activeResults.isEmpty()) {
            logger.debug("activeResults is null or empty");
        } else {
            for (Map.Entry<String,AuthenticationResult> entry : activeResults.entrySet()) {
                Subject activeSubject = entry.getValue().getSubject();
                Set<Principal> initialPrincipals = activeSubject.getPrincipals();
                if (initialPrincipals == null) {
                    logger.debug("initialPrincipals is null");
                } else {
                    for (Principal p : initialPrincipals) {
                        logger.debug("initialPrincipal: " + p.toString());
                        if (p instanceof AuthnContextClassRefPrincipal) {
                            existingAuthenticationClassPrincipals.add(p);
                        }
                    }
                }
            }
        }
        return existingAuthenticationClassPrincipals;
    }

    /**
     * Find out principals (authentication contexts) requested by SP.
     *
     * @param profileRequestContext     Shibboleth request context
     * @return semicolon-delimited String of auth class friendly names
     */
    private String resolveRequestAuthenticationContextClassList(ProfileRequestContext profileRequestContext) {
        AuthenticationContext ac = profileRequestContext.getSubcontext(AuthenticationContext.class);
        RequestedPrincipalContext rpc = ac.getSubcontext(RequestedPrincipalContext.class);
        String authenticationContextClassList = "";
        if (rpc != null) {
            for (Principal principal : rpc.getRequestedPrincipals()) {
                if (principal instanceof AuthnContextClassRefPrincipal) {
                    // eg. "urn:oid:1.2.246.517.3002.110.6" / "http://ftn.ficora.fi/2017/loa2"
                    String authenticationContextOid = principal.getName();
                    logger.debug("Requested principal: " + authenticationContextOid);
                    for (AuthMethod authMethod : AuthMethod.values()) {
                        if (authMethod.getOidValue().contentEquals(authenticationContextOid)) {
                            logger.debug("Requested oid friendly name: " + authMethod.toString());
                            if (authenticationContextClassList.isEmpty()) {
                                authenticationContextClassList += authMethod.toString();
                            } else {
                                authenticationContextClassList += ";" + authMethod.toString();
                            }
                        }
                    }
                }
            }
        }
        return authenticationContextClassList;
    }

    //Logger for testing
    private void debugLogRequest(HttpServletRequest request, ProfileRequestContext prc) {
        final Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            final String header = headerNames.nextElement();
            final String value = request.getHeader(header);
            logger.debug("Header name {} has value {}", header, value);
        }
        final Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            final String attribute = attributeNames.nextElement();
            logger.debug("Attribute name {} has value {}", attribute, request.getAttribute(attribute));
        }
        AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        RequestedPrincipalContext rpc = ac.getSubcontext(RequestedPrincipalContext.class);
        for (Principal p : rpc.getRequestedPrincipals()) {
            logger.debug("Requested principal: " + p.toString());
        }
    }

    private int getDiscoveryPageTimeout() {
        if (timeIntervalInit < 10) {
            return 5;
        } else {
            return timeIntervalInit - 5;
        }
    }

}
