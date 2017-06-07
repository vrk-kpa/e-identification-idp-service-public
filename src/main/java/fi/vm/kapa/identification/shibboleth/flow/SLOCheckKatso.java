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

import java.util.Iterator;

import javax.annotation.Nonnull;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SessionResolver;
import net.shibboleth.idp.session.criterion.SPSessionCriterion;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicates;

import fi.vm.kapa.identification.shibboleth.context.KatsoContext;
import fi.vm.kapa.identification.type.AuthMethod;
import fi.vm.kapa.identification.type.AuthMethod.IllegalOidException;

public class SLOCheckKatso extends AbstractProfileAction {
    
    private final Logger log = LoggerFactory.getLogger(SLOCheckKatso.class);
    
    private SessionResolver sessionResolver;

    private Function<ProfileRequestContext,CriteriaSet> sessionResolverCriteriaStrategy;
    
    private Function<ProfileRequestContext,LogoutRequest> logoutRequestLookupStrategy;
    
    private LogoutRequest logoutRequest;
    
    public SLOCheckKatso() {
        
        sessionResolverCriteriaStrategy = new Function<ProfileRequestContext,CriteriaSet>() {
            @Override
            public CriteriaSet apply(final ProfileRequestContext input) {
                if (logoutRequest != null && logoutRequest.getIssuer() != null && logoutRequest.getNameID() != null) {
                    return new CriteriaSet(new SPSessionCriterion(logoutRequest.getIssuer().getValue(),
                            logoutRequest.getNameID().getValue()));
                } else {
                    return new CriteriaSet();
                }
            }
        };
    
        logoutRequestLookupStrategy = Functions.compose(new MessageLookup<>(LogoutRequest.class),
                new InboundMessageContextLookup());
    }
    
    public void setSessionResolver(@Nonnull final SessionResolver resolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        sessionResolver = Constraint.isNotNull(resolver, "SessionResolver cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (!getActivationCondition().equals(Predicates.alwaysFalse())) {
            if (sessionResolver == null) {
                throw new ComponentInitializationException("SessionResolver cannot be null");
            }
        }
    }

    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        
        logoutRequest = logoutRequestLookupStrategy.apply(profileRequestContext);
        if (logoutRequest == null) {
            return false;
        } else if (logoutRequest.getNameID() == null) {
            return false;
        }

        return true;
    }
    
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        try {
            final Iterable<IdPSession> sessions =
                    sessionResolver.resolve(sessionResolverCriteriaStrategy.apply(profileRequestContext));
            final Iterator<IdPSession> sessionIterator = sessions.iterator();

            
            while (sessionIterator.hasNext()) {
                final IdPSession session = sessionIterator.next();

                for (AuthnContextClassRefPrincipal ap: session.getAuthenticationResult("authn/ext1").getSubject().getPrincipals(AuthnContextClassRefPrincipal.class)) {
                    AuthnContextClassRef ac = ap.getAuthnContextClassRef();
                    AuthMethod am = null;
                    try {
                        am = AuthMethod.fromOid( ac.getAuthnContextClassRef() );
                    } catch (IllegalOidException e) {
                        continue;
                    }

                    if ( am == AuthMethod.KATSOOTP || am == AuthMethod.KATSOPWD ) {
                        profileRequestContext.addSubcontext(new KatsoContext());
                        log.debug("Katso in use for IdP session {}", getLogPrefix(), session.getId());
                    }
                }
            }            
        } catch (final ResolverException e) {
            // We don't care
        }
    }
    
}