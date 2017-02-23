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
package fi.vm.kapa.identification.pagetest.utils;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VelocityServer {

    private final Server server;


    public VelocityServer(int port) {
        server = new Server(port);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("server starting");
        VelocityServer velocityServer = new VelocityServer(8080);
        Path staticDir;
        if (args.length == 0) {
            staticDir = Paths.get("../sevi-identification-ui/dev/");
        } else {
            if ("-h".contentEquals(args[0]) || "--help".contentEquals(args[0])) {
                System.out.println("Usage: velo [--help | path-to-dir-containing-resources]");
                System.exit(0);
            }
            staticDir = Paths.get(args[0]);
        }
        velocityServer.setup(staticDir);
        velocityServer.start();
        velocityServer.join();
    }

    public void start() throws Exception {
        server.start();
    }

    public void join() throws InterruptedException {
        server.join();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public Server getServer() {
        return server;
    }

    public void setStaticResourcesBase(String urlPath, String directoryName) {
        ContextHandler resourceContextHandler = new ContextHandler("/");
        ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setResourceBase(directoryName);
        resourceContextHandler.setHandler(resourceHandler);
        addHandler(resourceContextHandler);
    }

    public void setResourceHandler(String urlPath, HtmlProducer pageProducer) {
        ContextHandler attributeRelease = new ContextHandler(urlPath);
        attributeRelease.setHandler(new PageTestServer(pageProducer));
        addHandler(attributeRelease);
    }

    private void addHandler(Handler contextHandler) {
        List<Handler> handlers = new ArrayList<>(Arrays.asList(server.getHandlers()));
        handlers.add(contextHandler);
        ContextHandlerCollection contexts = new ContextHandlerCollection();
        contexts.setHandlers(handlers.toArray(new Handler[]{}));
        server.setHandler(contexts);
    }

    private void setup(Path staticDir) throws Exception {
        setStaticResourcesBase("/", staticDir.toString());
        AttributeRelease attributeReleaseProducer = new AttributeRelease(Paths.get("conf/shibboleth/views/"));
        attributeReleaseProducer.setPersonAttributes(AttributeRelease.getDefaultAttributes());
        setResourceHandler("/idp/profile/SAML2/Redirect/SSO", attributeReleaseProducer);
        setResourceHandler("/idp/profile/SAML2/Redirect/SLO", new LogoutPropagate());
    }
}
