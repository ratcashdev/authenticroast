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

import java.lang.reflect.Method;
import javax.servlet.ServletContext;


/**
 * Allows web-applications to register a PluggableAuthenticator to use
 * for requests to its resources.
 * You can also specify the class as init-parameter
 * <code>roast.authenticator.class</code>.
 *
 * @author Aike J Sommer
 */
public abstract class Registry {

    /**
     * Create or find an instance that will use context to store the
     * authenticator.
     *
     * @param context The ServletContext instance for the current web-app.
     */
    public static Registry forContext(ServletContext context) {
        try {
            Class c = Registry.class.getClassLoader().loadClass(
                    "name.aikesommer.authenticator.RegistryImpl");
            Method m = c.getDeclaredMethod("forContext", ServletContext.class);
            return (Registry) m.invoke(null, context);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }

    /**
     * Register a as authenticator for this Web-App.
     *
     * @param a The PluggableAuthenticator to use for this web-app.
     */
    public abstract void register(PluggableAuthenticator a);

    /**
     * Register f as principal-store factory for this Web-App.
     *
     * @param s The PrincipalStore.Factory to use for this web-app.
     */
    public abstract void register(PrincipalStore.Factory f);

    /**
     * This will be called by the AuthModule to create the principal-store
     * instance.
     *
     * @return A PrincipalStore instance from the previously registered
     *         class.
     */
    protected abstract PrincipalStore principalStore();

}
