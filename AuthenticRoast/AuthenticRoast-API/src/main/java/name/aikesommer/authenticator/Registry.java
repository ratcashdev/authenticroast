/**
 *    Copyright (C) 2007-2010 Aike J Sommer (http://aikesommer.name/)
 *
 *    This file is part of AuthenticRoast.
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 3 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General
 *    Public License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *    Boston, MA 02110-1301 USA
 *
 *    You can reach the author and get more information about this
 *    project at: http://aikesommer.name/
 */
package name.aikesommer.authenticator;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

/**
 * Allows web-applications to register a PluggableAuthenticator to use
 * for requests to its resources.
 * You can also specify the class as init-parameter
 * <code>roast.authenticator.class</code>.
 * 
 * @author Aike J Sommer
 */
public class Registry {

    private static final String AUTHENTICATOR_NOTE = Registry.class.getName() + ".AUTHENTICATOR";
    private static final String PRINCIPALSTORE_NOTE = Registry.class.getName() + ".PRINCIPALSTORE";

    private static ClassLoaderResolver resolver = null;

    protected static void setResolver(ClassLoaderResolver resolver) {
        Registry.resolver = resolver;
    }

    private ServletContext context;

    /**
     * Create or find an instance that will use context to store the
     * authenticator.
     *
     * @param context The ServletContext instance for the current web-app.
     */
    public static Registry forContext(ServletContext context) {
        return new Registry(context);
    }
    
    /**
     * Create an instance that will use context to store the authenticator
     * class.
     * 
     * @param context The ServletContext instance for the current web-app.
     */
    private Registry(ServletContext context) {
        this.context = context;
    }
    
    /**
     * Register a as authenticator for this Web-App.
     *
     * @param a The PluggableAuthenticator to use for this web-app.
     */
    public void register(PluggableAuthenticator a) {
        context.setAttribute(AUTHENTICATOR_NOTE, a);
    }

    /**
     * Register f as principal-store factory for this Web-App.
     *
     * @param s The PrincipalStore.Factory to use for this web-app.
     */
    public void register(PrincipalStore.Factory f) {
        context.setAttribute(PRINCIPALSTORE_NOTE, f);
    }

    /**
     * This will be called by the AuthModule to create the authenticator
     * instance.
     *
     * @return A PluggableAuthenticator instance from the previously registered
     *         class.
     */
    protected PluggableAuthenticator authenticator() {
        try {
            PluggableAuthenticator authenticator = (PluggableAuthenticator) context.getAttribute(
                    AUTHENTICATOR_NOTE);
            if (authenticator == null) {
                String name = context.getInitParameter("roast.authenticator.class");
//                context.
                Class<? extends PluggableAuthenticator> c = null;
                if (resolver != null) {
                    try {
                        c = (Class<? extends PluggableAuthenticator>) resolver.resolve(context).loadClass(name);
                    } catch (ClassNotFoundException ex) {
                    }
                }
                if (c == null) {
                    try {
                        c = (Class<? extends PluggableAuthenticator>) Thread.currentThread().getContextClassLoader().loadClass(name);
                    } catch (ClassNotFoundException ex) {
                        c = (Class<? extends PluggableAuthenticator>) Class.forName(name);
                    }
                }
                
                authenticator = c.newInstance();
                register(authenticator);
            }
            return authenticator;
        } catch (Throwable t) {
            Logger log = Logger.getLogger(getClass().getName());
            log.severe("failed to create authenticator: " + t);
            log.log(Level.FINE, "failed to create authenticator", t);
            return null;
        }
    }

    /**
     * This will be called by the AuthModule to create the principal-store
     * instance.
     *
     * @return A PrincipalStore instance from the previously registered
     *         class.
     */
    protected PrincipalStore principalStore(HttpSession session) {
        try {
            PrincipalStore.Factory factory = (PrincipalStore.Factory) context.getAttribute(
                    PRINCIPALSTORE_NOTE);
            if (factory == null) {
                String name = context.getInitParameter("roast.principal-store.factory");
                if (name == null) {
                    return new DefaultPrincipalStore(session);
                }
                
                Class<? extends PrincipalStore.Factory> c = (Class<? extends PrincipalStore.Factory>) Class.forName(name);
                factory = c.newInstance();
                register(factory);
            }
            return factory.factory(session);
        } catch (Throwable t) {
            Logger log = Logger.getLogger(getClass().getName());
            log.severe("failed to create principal-store: " + t);
            log.log(Level.FINE, "failed to create principal-store", t);
            return null;
        }
    }

}
