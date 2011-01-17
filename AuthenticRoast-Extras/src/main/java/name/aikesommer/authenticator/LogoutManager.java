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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Set;
import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;

/**
 * A very simple authenticator to allow for logouts.
 * Just have a link to "j_security_exit" as logout-link and this authenticator
 * should pick it up when clicked.
 * 
 * @author Aike J Sommer
 */
public class LogoutManager extends PluggableAuthenticator {

    public static final String LOGOUT_ACTION = "/j_security_exit";

    /**
     * Overwrite this to specify a different path to direct to after logging
     * the user out.
     */
    protected String getNextPath(AuthenticationManager manager, AuthenticationRequest request) {
        if (request.getHttpServletRequest().getParameter("_to") != null) {
            String to = request.getHttpServletRequest().getParameter("_to");
            String url = null;
            for (Map.Entry<String, String[]> entry : (Set<Map.Entry<String, String[]>>) request.
                    getHttpServletRequest().getParameterMap().entrySet()) {
                if (entry.getKey().startsWith("_p_") && entry.getKey().length() > 3 && entry.getValue().length > 0) {
                    String name;
                    String value;
                    try {
                        name = URLEncoder.encode(entry.getKey().substring(3), "UTF-8");
                        value = URLEncoder.encode(entry.getValue()[0], "UTF-8");
                    } catch (UnsupportedEncodingException ex) {
                        throw new RuntimeException(ex);
                    }

                    String param = name + "=" + value;
                    url = url == null ? (to + "?" + param) : (url + "&" + param);
                }
            }
            if (url == null) {
                url = to;
            }
            return url;
        }
        return "/";
    }

    /**
     * Overwrite this to perform anything necessary with your session-data. This
     * is called before the session is destroyed.
     */
    protected void onLogout(AuthenticationManager manager, AuthenticationRequest request) {
    }

    @Override
    public Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        return Status.None;
    }

    @Override
    public Status authenticate(AuthenticationManager manager, AuthenticationRequest request) {
        return Status.None;
    }

    @Override
    public ManageAction manage(AuthenticationManager manager, AuthenticationRequest request) {
        String path = request.getRequestPath();
        boolean logoutAction = path.endsWith(LOGOUT_ACTION);

        if (logoutAction) {
            onLogout(manager, request);
            manager.forward(request, getNextPath(manager, request));
            return ManageAction.Clear;
        }

        return ManageAction.None;
    }
}
