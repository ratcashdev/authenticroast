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
import javax.servlet.http.HttpServletResponse;
import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;
import name.aikesommer.authenticator.thirdparty.Base64;


/**
 * This class implements HTTP Basic authentication.
 * Just implement checkCredentials() and loadPrincipal() and everything
 * should work.
 *
 * @author Aike J Sommer
 */
public abstract class BasicAuthenticator extends PluggableAuthenticator {

    /**
     * This method checks the supplied credentials and returns true if they
     * are valid.
     *
     * @param username The username entered on the login-form.
     * @param password The password entered on the login-form.
     * @return true if the credentials are valid.
     */
    protected abstract boolean checkCredentials(AuthenticationManager manager,
            AuthenticationRequest request, String username, String password);

    /**
     * Create a SimplePrincipal from the username given.
     *
     * @param username The username entered on the login-form.
     * @return A SimplePrincipal instance representing the user.
     */
    protected abstract SimplePrincipal loadPrincipal(AuthenticationManager manager,
            AuthenticationRequest request, String username);

    /**
     * Return the realm-name used for basic authentication.
     *
     * @return The realm name shown at the browser popup dialog.
     */
    protected abstract String getRealmName();

    private String checkAuthentication(AuthenticationManager manager, AuthenticationRequest request) {
        String authHeader = request.getHttpServletRequest().getHeader("Authorization");
        if (authHeader != null) {
            String[] authTokens = authHeader.split(" ");
            if (authTokens.length < 2 || !authTokens[0].equals("Basic")) {
                return null;
            }

            String auth;
            try {
                auth = new String(Base64.decode(authTokens[1]));
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] authStrs = auth.split(":");
            if (authStrs.length != 2) {
                return null;
            }

            if (checkCredentials(manager, request, authStrs[0], authStrs[1])) {
                return authStrs[0];
            }
        }
        return null;
    }

    @Override
    public Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        String username;
        if ((username = checkAuthentication(manager, request)) != null) {
            manager.register(request, loadPrincipal(manager, request, username));
            return Status.Success;
        }
        return Status.None;
    }

    @Override
    public Status authenticate(AuthenticationManager manager, AuthenticationRequest request) {
        request.getHttpServletResponse().setHeader("WWW-Authenticate",
                "Basic realm=\"" + getRealmName() + "\"");
        try {
            request.getHttpServletResponse().sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return Status.Continue;
    }

    @Override
    public ManageAction manage(AuthenticationManager manager, AuthenticationRequest request) {
        String username = checkAuthentication(manager, request);
        if (username == null) {
            return ManageAction.Clear;
        }
        SimplePrincipal user = SimplePrincipal.getPrincipal(request.getHttpServletRequest());
        if (! user.getName().equals(username)) {
            return ManageAction.Clear;
        }
        return ManageAction.None;
    }

}
