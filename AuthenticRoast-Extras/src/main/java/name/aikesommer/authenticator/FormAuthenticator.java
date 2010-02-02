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

import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;

/**
 * This class allows for simple form-based logins.
 * Just implement checkCredentials() and loadPrincipal() and everything
 * should work.
 * 
 * @author Aike J Sommer
 */
public abstract class FormAuthenticator extends PluggableAuthenticator {

    private static final String PRINCIPAL_NOTE = PluggableAuthenticator.class.getName() + ".PRINCIPAL";
    public static final String LOGIN_ACTION = "/j_security_check";
    public static final String LOGIN_USERNAME = "j_username";
    public static final String LOGIN_PASSWORD = "j_password";

    /**
     * This method checks the supplied credentials and returns true if they
     * are valid.
     * 
     * @param username The username entered on the login-form.
     * @param password The password entered on the login-form.
     * @return true if the credentials are valid.
     */
    protected abstract boolean checkCredentials(AuthenticationManager manager, AuthenticationRequest request, String username, String password);
    
    /**
     * Create a SimplePrincipal from the username given.
     * 
     * @param username The username entered on the login-form.
     * @return A SimplePrincipal instance representing the user.
     */
    protected abstract SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, String username);
    
    /**
     * Overwrite this to specify a different login-page.
     */
    protected String getLoginPage() {
        return "/login.jsp";
    }

    /**
     * Overwrite this to specify a different error-page.
     */
    protected String getErrorPage() {
        return "/login-error.jsp";
    }

    @Override
    public Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        if (manager.matchesRequest(request) && request.getSessionMap().containsKey(PRINCIPAL_NOTE)) {
            manager.register(request, (SimplePrincipal) request.getSessionMap().get(PRINCIPAL_NOTE));
            request.getSessionMap().remove(PRINCIPAL_NOTE);
            manager.restoreRequest(request);
            return Status.Success;
        }

        String requestURI = request.getRequestPath();
        boolean loginAction = requestURI.endsWith(LOGIN_ACTION);

        if (loginAction) {
            String user = request.getParameter(LOGIN_USERNAME);
            String password = request.getParameter(LOGIN_PASSWORD);

            if (password != null) {
                if (checkCredentials(manager, request, user, password)) {
                    request.getSessionMap().put(PRINCIPAL_NOTE, loadPrincipal(manager, request, user));
                    String queryString = request.getHttpServletRequest().getQueryString();
                    if (queryString != null && queryString.length() > 0) {
                        manager.addQueryString(request, queryString);
                    }
                    manager.redirectToRequest(request);
                    return Status.Continue;
                }
            }

            manager.forward(request, getErrorPage());
            return Status.Continue;
        }

        return Status.None;
    }

    @Override
    public Status authenticate(AuthenticationManager manager, AuthenticationRequest request) {
        manager.saveRequest(request);
        manager.forward(request, getLoginPage());
        return Status.Continue;
    }

    @Override
    public ManageAction manage(AuthenticationManager manager, AuthenticationRequest request) {
        return ManageAction.None;
    }

}
