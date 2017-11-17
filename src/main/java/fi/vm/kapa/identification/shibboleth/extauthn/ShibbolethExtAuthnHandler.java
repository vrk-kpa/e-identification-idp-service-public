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
import fi.vm.kapa.identification.type.AuthMethod;
import fi.vm.kapa.identification.type.SessionStatus;
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
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet(name = "ShibbolethExtAuthnHandler", urlPatterns = {"/authn/External/*"})
public class ShibbolethExtAuthnHandler extends HttpServlet {

    private final static Logger logger = LoggerFactory.getLogger(ShibbolethExtAuthnHandler.class);
    private final static int HTTP_OK = 200;
    private final static String LANG_COOKIE_NAME = "E-Identification-Lang";
    private final static String DEFAULT_LANG = "fi";

    private String sharedSecret;
    private String hmacAlgorithm;
    private int timeIntervalBuilt;
    private int timeIntervalInit;
    private PhaseIdHistoryService historyService;
    private String spURLBase;
    private String defaultErrorBase;
    private String stepSessionInit;
    private String stepRedirectFromSP;
    private String stepGetSession;
    private String stepCancel;
    private String discoveryPagePath;
    private String timeoutPagePath;
    private String sp_login_path;
    private String proxyUrl;

    /* These strings define the error redirect URL query parameter that can be
     * used to guide the error page, the value matches the property key that
     * fetches the correct language variant for the error message
     */
    private String errorParamIdpExt;
    private String errorParamInternal;
    private String errorParamInvalidEID;
    private String errorParamPhaseID;
    private String errorParamCancel;
    private String errorParamCookiesDisabled;

    public void init(ServletConfig config) throws ServletException {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("/opt/identity-provider/identity-provider.properties"));
            spURLBase = props.getProperty("sp.redirect.url");
            discoveryPagePath = props.getProperty("discovery.page.path");
            timeoutPagePath = "/timeout";
            sp_login_path = props.getProperty("sp.login.path");
            defaultErrorBase = props.getProperty("default.error.url");
            stepSessionInit = props.getProperty("phase.id.step.one");
            stepRedirectFromSP = props.getProperty("phase.id.step.three");
            stepGetSession = props.getProperty("phase.id.step.four");
            stepCancel = props.getProperty("phase.id.step.five");
            errorParamInternal = props.getProperty("failure.param.internal");
            errorParamIdpExt = props.getProperty("failure.param.idp.ext");
            errorParamInvalidEID = props.getProperty("failure.param.entityid");
            errorParamPhaseID = props.getProperty("failure.param.phaseid");
            errorParamCancel = props.getProperty("failure.param.cancel");
            errorParamCookiesDisabled = props.getProperty("failure.param.cookiesdisabled");
            timeIntervalBuilt = Integer.parseInt(props.getProperty("phase.id.time.built.interval"));
            timeIntervalInit = Integer.parseInt(props.getProperty("phase.id.time.init.interval"));
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

        String redirectUrl;
        PhaseIdService phaseIdInitSession = null;
        PhaseIdService phaseIdBuiltSession = null;
        ProxyClient proxyClient = new ProxyClient(proxyUrl);

        // Check if cookies are set. If not, it means that cookies are disabled in the client and user needs to be
        // redirected to error page.
        if (request.getCookies() == null) {
            logger.debug("Cookies disabled, redirecting to error page");
            redirectUrl = createErrorURL(createLogTag(), errorParamCookiesDisabled);
            response.sendRedirect(redirectUrl);
            return;
        }

        try {
            // Proxy-generated token ID that must be checked first
            String tid = request.getParameter("tid");
            String status = request.getParameter("status");
            /** If token ID and status are empty, this is an initial call from IdP (1.) */
            if (StringUtils.isBlank(tid) && StringUtils.isBlank(status)) {
                /** Get conversation key from Shibboleth IdP (2.) */
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

                String requestedAuthenticationMethodSet = resolveRequestAuthenticationContextClassList(prc);
                //Get existing uid from IdP session. Set value to 0 (AuthMethod INIT) if null.
                String uid = existingAuthenticationSubjectName(prc);
                if (StringUtils.isBlank(uid)) {
                    uid = SessionStatus.INIT.getStatusAsNumericalString(); //"0"
                }
                logger.debug("Existing session uid: " + uid);
                redirectUrl = initialiseSession(proxyClient, uid, convKey, relyingParty, requestedAuthenticationMethodSet);
                logger.debug("(Initial redirectUrl to SP:  " + redirectUrl);
            }
            /** Token ID is not empty or a status is present,
             * the call is from SP (4.) or the authentication sequence was cancelled */
            else {
                String logTag = request.getParameter("tag");
                String pid = request.getParameter("pid");

                try {
                    phaseIdInitSession = new PhaseIdService(sharedSecret, timeIntervalInit, hmacAlgorithm);
                } catch (Exception e) {
                    logger.warn("Failed to initialize new phaseIdInitSession ", e);
                    throw new ExternalAuthenticationException();
                }

                try {
                    phaseIdBuiltSession = new PhaseIdService(sharedSecret, timeIntervalBuilt, hmacAlgorithm);
                } catch (Exception e) {
                    logger.warn("Failed to initialize new phaseIdBuiltSession ", e);
                    throw new ExternalAuthenticationException();
                }

                if (status != null && status.equals("cancel")) {
                    // authentication cancelled
                    // purge session from proxy and send authn failed SAML response
                    try {
                        cancel(proxyClient, tid, pid, phaseIdInitSession,
                            phaseIdBuiltSession, logTag, request, response);
                        return;
                    } catch (Exception e) {
                        logger.warn("<<{}>> Failed to purge session", logTag);
                        redirectUrl = createErrorURL(logTag, errorParamCancel);
                    }
                } else if (status != null && status.equals("timeout")) {
                    // session timed out on disco page
                    // purge session and redirect to timeout page
                    redirectUrl = timeout(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag);

                } else if (status != null && status.equals("return")) {
                    // return to original service provider from timeout page
                    // send authentication error SAML response
                    String key = request.getParameter("conversation");
                    try {
                        returnToService(key, request, response);
                        return;
                    } catch (Exception e) {
                        logger.warn("<<{}>> Failed to return to service: {}", logTag, e.getMessage());
                        redirectUrl = createErrorURL(logTag, errorParamIdpExt);
                    }
                } else {
                    String[] keyAndUid = new String[3];
                    redirectUrl = finaliseSession(proxyClient, tid, pid, phaseIdBuiltSession, logTag, keyAndUid);
                    logger.debug("Finalise redirectUrl (null if ok): " + redirectUrl);
                /* This redirect URL is always null if everything went according
                 * to plans, if it's not then the user must be redirected to standard
                 * error page with the given additional info
                 */
                    if (StringUtils.isBlank(redirectUrl)) {
                    /* The first value in the array is always the Shibboleth conversation key
                     * that was fetched in the session init and the second one is always the
                     * user's generated UID hash that is used to fetch the attributes
                     */
                        /** External authentication success. Give control back to Shibboleth IdP (7.) */
                        //Get existing active authentication class principals from IdP session
                        ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(keyAndUid[0], request);
                        Set<Principal> principals = getExistingActiveAuthenticationClassPrincipals(prc);
                        logger.debug("Existing principals in principal set: " + !principals.isEmpty());
                        principals.add(new UsernamePrincipal(keyAndUid[1]));
                        principals.add(new AuthnContextClassRefPrincipal(AuthMethod.valueOf(keyAndUid[2]).getOidValue()));
                        Subject subject = new Subject();
                        subject.getPrincipals().addAll(principals);
                        request.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
                        ExternalAuthentication.finishExternalAuthentication(keyAndUid[0], request, response);
                    /* This explicit return must be used since the 'finishExternalAuthentication' method
                     * contains 'response.sendRedirect()' method call
                     */
                        return;
                    }
                }
            }
        } catch (ExternalAuthenticationException eae) {
            logger.warn("Failure in external authentication", eae);
            redirectUrl = createErrorURL(createLogTag(), errorParamIdpExt);

        }
        response.sendRedirect(redirectUrl);
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

    private void cancel(ProxyClient proxyClient, String tid, String pid, PhaseIdService phaseIdInitSession,
                        PhaseIdService phaseIdBuiltSession, String logTag,
                        HttpServletRequest request, HttpServletResponse response) throws Exception {
        String key = purgeSession(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag);
        logger.debug("Canceling authentication from Shibboleth IdP with conversation key {}", key);
        request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "User canceled authentication");
        ExternalAuthentication.finishExternalAuthentication(key, request, response);
    }

    private String timeout(ProxyClient proxyClient, String tid, String pid, PhaseIdService phaseIdInitSession,
                           PhaseIdService phaseIdBuiltSession, String logTag) {
        String redirectUrl;
        try {
            String key = purgeSession(proxyClient, tid, pid, phaseIdInitSession, phaseIdBuiltSession, logTag);
            redirectUrl = timeoutPagePath + "?conversation=" + key;
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

    private String initialiseSession(ProxyClient proxyClient,
                                     String uid, String convKey,
                                     String relyingParty,
                                     String requestedAuthenticationMethodStr) {

        String redirectUrl;
        String logTag = createLogTag();
        // Relying party parameter must match the allowed entity ID format
        if (UrlParamService.isValidEntityId(relyingParty)) {
            String spCallUrl = sessionInit(proxyClient, uid, relyingParty, convKey, logTag, requestedAuthenticationMethodStr);
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

    private String finaliseSession(ProxyClient proxyClient,
                                   String tid, String pid,
                                   PhaseIdService phaseIdBuiltSession,
                                   String logTag,
                                   String[] keyAndUid) {
        /* This redirect URL is used only if something goes wrong in the session fetch,
         * this URL is null in successful session fetch
         */
        String redirectUrl = null;
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
                if (phaseIdBuiltSession.validateTidAndPid(tid, pid) &&
                    phaseIdBuiltSession.verifyPhaseId(pid, tid, stepRedirectFromSP)) {
                    phaseId = phaseIdBuiltSession.newPhaseId(tid, stepGetSession);
                }
            } catch (Exception e) {
                logger.warn("<<{}>> Failed to verify or generate next phase ID", logTag, e);
                redirectUrl = createErrorURL(logTag, errorParamPhaseID);
            }
        } else {
            logger.warn("Received already consumed token and phase IDs!!");
        }
        if (phaseId != null) {
            /** Fetch session data from Proxy (6.) */
            ProxyMessageDTO message = sessionFetch(proxyClient, tid, phaseId, logTag);
            keyAndUid[0] = message.getConversationKey();
            keyAndUid[1] = message.getUid();
            keyAndUid[2] = message.getUsedAuthenticationMethod();

            logger.debug("--conversationKey: " + keyAndUid[0] + ", uid: " + keyAndUid[1] + ", used auth method: " + keyAndUid[2]);
            // This array is always fixed in length and it must be kept that way
            if (StringUtils.isBlank(keyAndUid[0]) || StringUtils.isBlank(keyAndUid[1]) || StringUtils.isBlank(keyAndUid[2])) {
                logger.warn("<<{}>> Getting session identifiers failed", logTag);
                redirectUrl = createErrorURL(logTag, errorParamInternal);
            }
        } else {
            logger.warn("<<{}>> Phase ID is not valid", logTag);
            redirectUrl = createErrorURL(logTag, errorParamPhaseID);
        }
        return redirectUrl;
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
            phaseIdInitSession.verifyPhaseId(pid, tid, stepSessionInit)) {
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
    private String sessionInit(ProxyClient proxyClient,
                               String uid,
                               String relyingParty,
                               String conversationKey,
                               String logTag,
                               final String requestedAuthenticationMethodSet) {

        String spCallUrl = null;
        ProxyMessageDTO responseEntity = null;
        try {
            responseEntity = proxyClient.addSession(relyingParty, uid, conversationKey, requestedAuthenticationMethodSet, logTag);

            if (responseEntity != null) {
                /**
                 * generating a link to discovery-page containing Entityid (relyingParty) of original service that is requesting authentication
                 */
                spCallUrl = discoveryPagePath + "?entityId=" + java.net.URLEncoder.encode(relyingParty, StandardCharsets.UTF_8.toString()) + "&return=" + java.net.URLEncoder.encode(sp_login_path, StandardCharsets.UTF_8.toString());
                final String extraPart = spURLBase + responseEntity.getTokenId() + "&pid=" + responseEntity.getPhaseId() + "&tag=" + logTag;
                spCallUrl = spCallUrl + "&timeout=" + getDiscoveryPageTimeout();
                spCallUrl = spCallUrl + "&target=" + java.net.URLEncoder.encode(extraPart, StandardCharsets.UTF_8.toString());
                spCallUrl = spCallUrl + "&authMethdReq=" + responseEntity.getAuthenticationMethods();
            }
        } catch (IOException ioe) {
            logger.warn("<<{}>> Failed to connect to Proxy for session init", logTag, ioe);
        }
        return spCallUrl;
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
        String langFromCookie = null;
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

            if (StringUtils.isBlank(vetumaLang)) {
                vetumaLang = DEFAULT_LANG;
            }
            logger.debug("Resolved vetuma-style language parameter from authentication request - " + vetumaLang);
            return vetumaLang;
        } else {
            if (StringUtils.isBlank(langFromCookie)) {
                logger.debug("Could not find language parameter in authentication request, using default language - " + DEFAULT_LANG);
                return DEFAULT_LANG;
            } else {
                return langFromCookie;
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
     * @param profileRequestContext
     * @return userPrincipal name of existing session
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
     * @param profileRequestContext
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
     * @param profileRequestContext
     * @return semicolon-delimited String of auth class friendly names
     */
    private String resolveRequestAuthenticationContextClassList(ProfileRequestContext profileRequestContext) {
        AuthenticationContext ac = profileRequestContext.getSubcontext(AuthenticationContext.class);
        RequestedPrincipalContext rpc = ac.getSubcontext(RequestedPrincipalContext.class);
        String authenticationContextClassList = "";
        Pattern oid = Pattern.compile("urn:oid:(?:\\d+\\.)+\\d+");
        if (rpc != null) {
            for (Principal principal : rpc.getRequestedPrincipals()) {
                logger.debug("Requested principal: " + principal.toString());
                if (principal instanceof AuthnContextClassRefPrincipal) {
                    Matcher matcher = oid.matcher(principal.getName());
                    if (matcher.find()) {
                        logger.debug("Requested oid: " + matcher.group(0));
                        String authenticationContextOid = matcher.group(0);
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

    int getDiscoveryPageTimeout() {
        if (timeIntervalInit < 10) {
            return 5;
        } else {
            return timeIntervalInit - 5;
        }
    }

}
