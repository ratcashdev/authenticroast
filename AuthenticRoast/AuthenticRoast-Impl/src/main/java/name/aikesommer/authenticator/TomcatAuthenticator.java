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

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Principal;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import org.apache.catalina.Authenticator;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;


/**
 * This is the main class called by the container. You probably dont wanna
 * call this class directly.
 * 
 * @author Aike J Sommer
 */
public class TomcatAuthenticator extends ValveBase implements Authenticator {

    static {
        RegistryImpl.setResolver(new ClassLoaderResolver() {

            public ClassLoader resolve(ServletContext context) {
                try {
                    Field appContextField =
                            context.getClass().getDeclaredField("context");
                    appContextField.setAccessible(true);
                    ApplicationContext appContext =
                            (ApplicationContext) appContextField.get(context);
                    appContextField.setAccessible(false);
                    Field stdContextField = appContext.getClass().
                            getDeclaredField("context");
                    stdContextField.setAccessible(true);
                    StandardContext stdContext =
                            (StandardContext) stdContextField.get(appContext);
                    appContextField.setAccessible(false);
                    return stdContext.getLoader().getClassLoader();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }

        });
    }

    private Context context;

    private AuthenticationManagerBase manager = new AuthenticationManagerBase() {

        @Override
        public void register(AuthenticationRequest request, SimplePrincipal simplePrincipal) {
            TomcatAuthenticator.this.register(request, simplePrincipal);
            super.register(request, simplePrincipal);
        }

    };

    protected void register(AuthenticationRequest request,
            SimplePrincipal simplePrincipal) {
        try {
            Tomcat6Request req =
                    (Tomcat6Request) request;
            req.getCatalinaRequest().setAuthType("ROAST");
            req.getCatalinaRequest().setUserPrincipal(simplePrincipal);
            Session session = req.getCatalinaRequest().getSessionInternal(true);
            session.setAuthType("ROAST");
            session.setPrincipal(simplePrincipal);
            session.setNote(Constants.SESS_USERNAME_NOTE, simplePrincipal.getName());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void setContainer(Container container) {
        this.context = (Context) container;
        super.setContainer(container);
    }

    private boolean checkRoles(Request request, Response response,
            SecurityConstraint[] constraints, Principal principal) {
        if (constraints == null) {
            return true;
        }

        for (int i = 0; i < constraints.length; i++) {
            SecurityConstraint constraint = constraints[i];
            String[] roles = constraint.getAllRoles() ? context.findSecurityRoles()
                    : constraint.findAuthRoles();
            if (roles == null) {
                roles = new String[0];
            }

            for (int j = 0; j < roles.length; j++) {
                String role = roles[j];
                if (checkRole(principal, role)) {
                    return true;
                }
            }

            response.setStatus(Response.SC_FORBIDDEN);
            return false;
        }

        return true;
    }

    private boolean checkRole(Principal principal, String role) {
        if (principal instanceof SimplePrincipal) {
            return ((SimplePrincipal) principal).getGroups().contains(role);
        } else if (principal instanceof GenericPrincipal) {
            for (int i = 0; i < ((GenericPrincipal) principal).getRoles().length; i++) {
                String hasRole = ((GenericPrincipal) principal).getRoles()[i];
                if (hasRole.equals(role)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (null == request.getCharacterEncoding()) {
            request.setCharacterEncoding("UTF-8");
        }

        Realm realm = context.getRealm();
        SecurityConstraint[] constraints =
                realm.findSecurityConstraints(request, this.context);

        RegistryImpl registry = RegistryImpl.forContext(request.getContext().
                getServletContext());
        Tomcat6Request authReq =
                new AuthenticationRequestImpl.Tomcat6(request, response,
                constraints != null, registry.isCrossContext());
        registry.createPrincipalStore(authReq);

        PluggableAuthenticator authenticator = registry.authenticator();

        if (!realm.hasUserDataPermission(request, response,
                constraints)) {
            return;
        }

        if (authenticator == null) {
            if (constraints == null) {
                getNext().invoke(request, response);
                return;
            } else {
                response.setStatus(Response.SC_FORBIDDEN);
                return;
            }
        }

        authenticator.begin(manager, authReq);

        boolean finished = false;
        try {
            SimplePrincipal simplePrincipal = registry.principalStore().fetch();
            if (simplePrincipal != null) {
                AuthenticationRequest.ManageAction action = authenticator.manage(manager, authReq);
                switch (action) {
                    case None:
                        register(authReq, simplePrincipal);

                        if (!checkRoles(request, response, constraints,
                                simplePrincipal)) {
                            return;
                        }

                        authenticator.finish(manager, authReq);
                        finished = true;
                        getNext().invoke(request, response);
                        return;
                    case Clear:
                        registry.principalStore().invalidate();
                        if (authReq.isForwarded()) {
                            return;
                        }
                }
            }

            switch (authenticator.tryAuthenticate(manager, authReq)) {
                case Continue:
                    return;
                case Failure:
                    response.setStatus(Response.SC_FORBIDDEN);
                    return;
                case None:
                    if (constraints != null) {
                        switch (authenticator.authenticate(manager, authReq)) {
                            case Continue:
                                return;
                            case Success:
                                break;
                            default:
                                response.setStatus(Response.SC_FORBIDDEN);
                                return;
                        }
                    }
            }

            simplePrincipal = registry.principalStore().fetch();
            if (!checkRoles(request, response, constraints, simplePrincipal)) {
                return;
            }
        } catch (Throwable t) {
            finished = true;
            authenticator.abort(manager, authReq, t);
            throw new RuntimeException(t);
        } finally {
            if (!finished) {
                authenticator.finish(manager, authReq);
            }
        }

        getNext().invoke(request, response);
    }

}
