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


/**
 * Allows web-applications to register a PluggableAuthenticator to use
 * for requests to its resources.
 * You can also specify the class as init-parameter
 * <code>roast.authenticator.class</code>.
 * 
 * @author Aike J Sommer
 */
public class RegistryImpl extends Registry {

    private static final String AUTHENTICATOR_NOTE = RegistryImpl.class.getName() + ".AUTHENTICATOR";

    private static final String CROSS_CONTEXT_NOTE = RegistryImpl.class.getName() + ".CROSS_CONTEXT";

    private static final String PRINCIPALSTORE_FACTORY_NOTE = RegistryImpl.class.getName()
            + ".PRINCIPALSTORE_FACTORY";

    private static final String PRINCIPALSTORE_NOTE = RegistryImpl.class.getName()
            + ".PRINCIPALSTORE";

	private static final String BEAN_MANAGER_NOTE = "javax.enterprise.inject.spi.BeanManager";
	
    private static ClassLoaderResolver resolver = null;

    /**
     * Create or find an instance that will use context to store the
     * authenticator.
     *
     * @param context The ServletContext instance for the current web-app.
	 * @return 
     */
    public static RegistryImpl forContext(ServletContext context) {
        return new RegistryImpl(context);
    }

    protected static void setResolver(ClassLoaderResolver resolver) {
        RegistryImpl.resolver = resolver;
    }

    private ServletContext context;

    /**
     * Create an instance that will use context to store the authenticator
     * class.
     * 
     * @param context The ServletContext instance for the current web-app.
     */
    public RegistryImpl(ServletContext context) {
        this.context = context;
    }

    /**
     * Register a as authenticator for this Web-App.
     *
     * @param a The PluggableAuthenticator to use for this web-app.
     */
	@Override
    public void register(PluggableAuthenticator a) {
        context.setAttribute(AUTHENTICATOR_NOTE, a);
    }

    /**
     * Register f as principal-store factory for this Web-App.
     *
     * @param s The PrincipalStore.Factory to use for this web-app.
     */
	@Override
    public void register(PrincipalStore.Factory f) {
        context.setAttribute(PRINCIPALSTORE_FACTORY_NOTE, f);
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
                String className = context.getInitParameter("roast.authenticator.class");
                if (className != null) {
                    Class<? extends PluggableAuthenticator> c = null;
                    if (resolver != null) {
                        try {
                            c = (Class<? extends PluggableAuthenticator>) resolver.resolve(context).loadClass(
                                    className);
                        } catch (ClassNotFoundException ex) {
                        }
                    }
                    if (c == null) {
                        try {
                            c = (Class<? extends PluggableAuthenticator>) Thread.currentThread().getContextClassLoader().loadClass(
                                    className);
                        } catch (ClassNotFoundException ex) {
                            c = (Class<? extends PluggableAuthenticator>) Class.forName(className);
                        }
                    }

                    authenticator = c.newInstance();
                } else {
                    String delegateName = context.getInitParameter("roast.delegate");

                    if (delegateName != null) {
                        ServletContext delegate = context.getContext(delegateName);
                        if (delegate == null) {
                            throw new IllegalArgumentException("The context '" + delegateName
                                    + "' does not exist!");
                        }

                        RegistryImpl delegateRegistry = RegistryImpl.forContext(delegate);
                        if (delegateRegistry.isDelegate()) {
                            authenticator = new DelegatingAuthenticator(
                                    delegateRegistry.authenticator(), delegate);
                        } else {
                            throw new IllegalArgumentException("The context '" + delegateName
                                    + "' does not allow to be used as a delegate!");
                        }
                    }
                }

                if (authenticator != null) {
                    register(authenticator);
                }
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
     * Get whether cross-context authentication should be enabled.
     */
    protected boolean isCrossContext() {
        Boolean result = (Boolean) context.getAttribute(CROSS_CONTEXT_NOTE);

        if (result == null) {
            result = context.getInitParameter("roast.delegate") != null || isDelegate();
        }

        result = result == null ? false : result;
        context.setAttribute(CROSS_CONTEXT_NOTE, result);
        return result;
    }

    /**
     * Get whether this context allows to be used as a delegate.
     */
    private boolean isDelegate() {
        return "true".equals(context.getInitParameter("roast.is-delegate"));
    }

    /**
     * This will be called by the AuthModule to create the principal-store
     * instance.
     *
     * @return A PrincipalStore instance from the previously registered
     *         class.
     */
    protected PrincipalStore principalStore() {
        ThreadLocal<PrincipalStore> stores = (ThreadLocal<PrincipalStore>) context.getAttribute(
                PRINCIPALSTORE_NOTE);
        if (stores != null) {
            return stores.get();
        }

        return null;
    }

    protected void createPrincipalStore(AuthenticationRequest request) {
        ThreadLocal<PrincipalStore> stores = (ThreadLocal<PrincipalStore>) context.getAttribute(
                PRINCIPALSTORE_NOTE);
        if (stores == null) {
            stores = new ThreadLocal<PrincipalStore>();
            context.setAttribute(PRINCIPALSTORE_NOTE, stores);
        }
        stores.remove();

        PrincipalStore store = null;
        try {
            PrincipalStore.Factory factory = (PrincipalStore.Factory) context.getAttribute(
                    PRINCIPALSTORE_FACTORY_NOTE);
            if (factory == null) {
                String name = context.getInitParameter("roast.principal-store.factory");
                if (name == null) {
                    store = isCrossContext() ? 
                        new CrossContextPrincipalStore(request.getHttpServletRequest(), request.getHttpServletResponse()) :
                        new DefaultPrincipalStore(request.getHttpServletRequest().getSession());
                } else {
                    Class<? extends PrincipalStore.Factory> c = (Class<? extends PrincipalStore.Factory>) Class.forName(
                            name);
                    factory = c.newInstance();
                    register(factory);
                }
            }
            if (store == null && factory != null) {
                store = factory.factory(request);
            }
        } catch (Throwable t) {
            Logger log = Logger.getLogger(getClass().getName());
            log.severe("failed to create principal-store: " + t);
            log.log(Level.FINE, "failed to create principal-store", t);
        }

        if (store != null) {
            stores.set(store);
        }
    }

}
