# Pull tomcat base image

FROM e-identification-docker-virtual.vrk-artifactory-01.eden.csc.fi/e-identification-tomcat-idp-3.4.1-base-image

# Copy files

COPY target/site /site
COPY target/kapa-identity-provider-jar-with-dependencies.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/kapa-identity-provider-jar-with-dependencies.jar
COPY idp-authn-impl-discovery-1.0-SNAPSHOT/ /opt/shibboleth-idp
COPY conf /tmp/conf
RUN mkdir -p /opt/shibboleth-idp/edit-webapp/WEB-INF/jsp && \
    mkdir -p /opt/identity-provider && \
    mkdir -p /usr/share/tomcat/properties && \
    mkdir -p /usr/share/tomcat/conf/Catalina/localhost && \
    mkdir -p /opt/shibboleth-idp/views/intercept && \
    mkdir -p /opt/shibboleth-idp/views/logout && \
    mkdir -p /opt/shibboleth-idp/bin && \
    mkdir -p /opt/shibboleth-idp/flows/authn/ext1 && \
    mkdir -p /opt/shibboleth-idp/flows/authn/ext2 && \
    mkdir -p /opt/shibboleth-idp/flows/intercept/attribute-release && \
    mkdir -p /opt/shibboleth-idp/flows/intercept/vtjverify && \
    mkdir -p /opt/shibboleth-idp/flows/intercept/eidas-session-destroy && \
    mkdir -p /data00/templates/store/ && \
    cp /tmp/conf/tomcat/catalina.properties /usr/share/tomcat/conf/catalina.properties && \
    cp /tmp/conf/tomcat/idp.xml /usr/share/tomcat/conf/Catalina/localhost/idp.xml && \
    cp -r /tmp/conf/shibboleth/conf/ /opt/shibboleth-idp/conf && \
    cp /tmp/conf/shibboleth/conf/errors.xml /opt/shibboleth-idp/conf/errors.xml && \
    cp /tmp/conf/shibboleth/webapp/web.xml /opt/shibboleth-idp/edit-webapp/WEB-INF/web.xml && \
    cp /tmp/conf/shibboleth/views/intercept/attribute-release.vm /opt/shibboleth-idp/views/intercept/attribute-release.vm && \
    cp /tmp/conf/shibboleth/views/logout-propagate.vm /opt/shibboleth-idp/views/logout-propagate.vm && \
    cp /tmp/conf/shibboleth/views/logout/propagate.vm /opt/shibboleth-idp/views/logout/propagate.vm && \
    cp /tmp/conf/shibboleth/views/include.vm /opt/shibboleth-idp/views/include.vm && \
    cp /tmp/conf/shibboleth/views/header.html /opt/shibboleth-idp/views/header.html && \
    cp /tmp/conf/shibboleth/views/footer.html /opt/shibboleth-idp/views/footer.html && \
    cp /tmp/conf/shibboleth/idp-rebuild.sh /opt/shibboleth-idp/bin/idp-rebuild.sh && \
    cp /tmp/conf/tomcat/logging.properties /usr/share/tomcat/conf/logging.properties && \
    cp /tmp/conf/shibboleth/flows/authn/ext1/ext1-beans.xml /opt/shibboleth-idp/flows/authn/ext1/ext1-beans.xml && \
    cp /tmp/conf/shibboleth/flows/authn/ext1/ext1-flow.xml /opt/shibboleth-idp/flows/authn/ext1/ext1-flow.xml && \
    cp /tmp/conf/shibboleth/flows/authn/ext2/ext2-beans.xml /opt/shibboleth-idp/flows/authn/ext2/ext2-beans.xml && \
    cp /tmp/conf/shibboleth/flows/authn/ext2/ext2-flow.xml /opt/shibboleth-idp/flows/authn/ext2/ext2-flow.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/attribute-release/attribute-release-beans.xml /opt/shibboleth-idp/flows/intercept/attribute-release/attribute-release-beans.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/attribute-release/attribute-release-flow.xml /opt/shibboleth-idp/flows/intercept/attribute-release/attribute-release-flow.xml && \
    cp /tmp/conf/shibboleth/conf/intercept/consent-intercept-config.xml /opt/shibboleth-idp/conf/intercept/consent-intercept-config.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/vtjverify/vtjverify-beans.xml /opt/shibboleth-idp/flows/intercept/vtjverify/vtjverify-beans.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/vtjverify/vtjverify-flow.xml /opt/shibboleth-idp/flows/intercept/vtjverify/vtjverify-flow.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/eidas-session-destroy/eidas-session-destroy-beans.xml /opt/shibboleth-idp/flows/intercept/eidas-session-destroy/eidas-session-destroy-beans.xml && \
    cp /tmp/conf/shibboleth/flows/intercept/eidas-session-destroy/eidas-session-destroy-flow.xml /opt/shibboleth-idp/flows/intercept/eidas-session-destroy/eidas-session-destroy-flow.xml && \
    cp /tmp/conf/shibboleth/conf/intercept/profile-intercept.xml /opt/shibboleth-idp/conf/intercept/profile-intercept.xml && \
    cp /tmp/conf/shibboleth/conf/intercept/intercept-events-flow.xml /opt/shibboleth-idp/conf/intercept/intercept-events-flow.xml && \
    cp /tmp/conf/shibboleth/conf/audit.xml /opt/shibboleth-idp/conf/audit.xml && \
:                             && \
: Templates                   && \
:                             && \
    cp /tmp/conf/shibboleth/idp-install.properties.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/idp-install.sh.template /data00/templates/store/ && \
    cp /tmp/conf/tomcat/identity-provider.properties.template /data00/templates/store/ && \
    cp /tmp/conf/tomcat/server.xml.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/conf_templates/access-control.xml.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/conf_templates/idp.properties.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/conf_templates/metadata-providers.xml.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/conf_templates/attribute-resolver-ext-connector.xml.template /data00/templates/store/ && \
    cp /tmp/conf/shibboleth/views/error.jsp.template /data00/templates/store/views_error.jsp.template && \
    cp /tmp/conf/shibboleth/webapp/error.jsp.template /data00/templates/store/webapp_error.jsp.template && \
    cp /tmp/conf/shibboleth/idp-setenv.sh.template /data00/templates/store/ && \
    cp /tmp/conf/logging/shibboleth_logback.xml.template /data00/templates/store/ && \
    cp -r /tmp/conf/ansible /data00/templates/store/ansible && \
:                             && \
: Create symlinks to mounted host deploy dir && \
:                             && \
    mkdir -p /opt/identity-provider && \
    mkdir -p /usr/share/tomcat/properties && \
    ln -sf /data00/deploy/logout.vm /opt/shibboleth-idp/views/logout.vm && \
    ln -sf /data00/deploy/idp-install.properties /usr/local/src/shibboleth-identity-provider/bin/idp-install.properties && \
    ln -sf /data00/deploy/idp-install.sh /usr/local/src/shibboleth-identity-provider/bin/idp-install.sh && \
    ln -sf /data00/deploy/identity-provider.properties /opt/identity-provider/identity-provider.properties && \
    ln -sf /data00/deploy/server.xml /usr/share/tomcat/conf/server.xml && \
    ln -sf /data00/deploy/metadata /opt/shibboleth-idp/metadata && \
    ln -sf /data00/deploy/access-control.xml /opt/shibboleth-idp/conf/access-control.xml && \
    ln -sf /data00/deploy/idp.properties /opt/shibboleth-idp/conf/idp.properties && \
    ln -sf /data00/deploy/metadata-providers.xml /opt/shibboleth-idp/conf/metadata-providers.xml && \
    ln -sf /data00/deploy/attribute-resolver-ext-connector.xml /opt/shibboleth-idp/conf/attribute-resolver-ext-connector.xml && \
    ln -sf /data00/deploy/views_error.jsp /opt/shibboleth-idp/edit-webapp/WEB-INF/jsp/error.jsp && \
    ln -sf /data00/deploy/webapp_error.jsp /opt/shibboleth-idp/edit-webapp/WEB-INF/error.jsp && \
    ln -sf /data00/deploy/idp-setenv.sh /usr/share/tomcat/bin/setenv.sh && \
    ln -sf /data00/deploy/kapa-ca /opt/kapa-ca && \
    ln -sf /data00/deploy/credentials/tomcat_keystore /usr/share/tomcat/properties/tomcat_keystore && \
    ln -sf /data00/deploy/shibboleth_logback.xml /opt/shibboleth-idp/conf/logback.xml && \
    ln -sf /data00/deploy/relying-party.xml /opt/shibboleth-idp/conf/relying-party.xml && \
    ln -sf /data00/deploy/global.xml /opt/shibboleth-idp/conf/global.xml && \
:                             && \
: File ownership              && \
:                             && \
    chown -R tomcat:tomcat /usr/local/src && \
    chown -R tomcat:tomcat /opt/shibboleth-idp/edit-webapp/WEB-INF/jsp && \
    chown -R tomcat:tomcat /usr/share/tomcat && \
    chown -R tomcat:tomcat /opt/identity-provider && \
    chown -R tomcat:tomcat /opt/shibboleth-idp && \
    rm -fr /usr/share/tomcat/webapps/* && \
    rm -fr /usr/share/tomcat/server/webapps/* && \
    rm -fr /usr/share/tomcat/conf/Catalina/localhost/host-manager.xml && \
    rm -fr /usr/share/tomcat/conf/Catalina/localhost/manager.xml

# Start things up. Run IdP install routine, link credentials, delete non-preferred error template,
# rebuild IdP and fix post-installation file ownership. Finally start tomcat.

CMD \
    mkdir -p /data00/logs && \
    chown -R tomcat:tomcat /data00/deploy && \
    chmod -R 777 /data00/logs && \
    sh /usr/local/src/shibboleth-identity-provider/bin/idp-install.sh && \
    ln -sf /data00/deploy/credentials/* /opt/shibboleth-idp/credentials && \
    rm -f /opt/shibboleth-idp/views/error.vm && \
    sh /opt/shibboleth-idp/bin/idp-rebuild.sh && \
    cp /tmp/conf/shibboleth/system/flows/logout/logout-flow.xml /opt/shibboleth-idp/system/flows/logout/logout-flow.xml && \
    cp /tmp/conf/shibboleth/system/flows/logout/slo-front-abstract-flow.xml /opt/shibboleth-idp/system/flows/saml/saml2/slo-front-abstract-flow.xml && \
    cp /tmp/conf/shibboleth/system/flows/logout/slo-front-abstract-beans.xml /opt/shibboleth-idp/system/flows/saml/saml2/slo-front-abstract-beans.xml && \
    chown -R tomcat:tomcat /opt/identity-provider && \
    chown -R tomcat:tomcat /opt/shibboleth-idp && \
    service tomcat start && tail -f /etc/hosts
