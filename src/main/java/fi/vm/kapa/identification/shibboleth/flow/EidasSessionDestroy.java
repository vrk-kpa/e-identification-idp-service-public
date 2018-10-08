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

package fi.vm.kapa.identification.shibboleth.flow;

import com.google.common.base.Function;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.session.SessionException;
import net.shibboleth.idp.session.SessionManager;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.idp.session.IdPSession;

@SuppressWarnings("rawtypes")
public class EidasSessionDestroy extends AbstractProfileAction {
     
    /**
     * Class logger.
     */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(EidasSessionDestroy.class);

    /**
     * SessionManager.
     */
    @Nonnull
    private SessionManager sessionManager;

    /**
     * Lookup function for SessionContext.
     */
    @Nonnull
    private Function<ProfileRequestContext,SessionContext> sessionContextLookupStrategy;

    /**
     * SessionContext to operate on.
     */
    @Nullable
    private SessionContext sessionCtx;

    public void setSessionManager(@Nonnull final SessionManager manager) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        sessionManager = Constraint.isNotNull(manager, "SessionManager cannot be null");
    }

    public void setSessionContextLookupStrategy(
        @Nonnull final Function<ProfileRequestContext,SessionContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        sessionContextLookupStrategy = Constraint.isNotNull(strategy,
            "SessionContext lookup strategy cannot be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (sessionManager == null) {
            throw new ComponentInitializationException("SessionManager cannot be null");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("Entering EidasDestroySession doExecute");
        sessionCtx = profileRequestContext.getSubcontext(SessionContext.class);
        try {
            IdPSession idpSession = sessionCtx.getIdPSession();
            if (idpSession != null) {
                String idpSessionId = idpSession.getId();
                if (idpSessionId != null) {
                    log.debug("Destroying eLoA session");
                    sessionManager.destroySession(idpSessionId, true);
                }
            }
        } catch (SessionException e) {
            log.warn("{} Failed to destroy session {}", getLogPrefix(), sessionCtx.getIdPSession().getId(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
        }
    }
}
