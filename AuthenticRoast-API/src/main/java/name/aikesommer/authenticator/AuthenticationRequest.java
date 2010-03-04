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

import java.util.Map;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The class representing the request for authentication to be passed to the
 * authenticator-object in aur web-app. This basically encapsulates some 
 * of the involved objects for simplicity.
 * 
 * @author Aike J Sommer
 */
public interface AuthenticationRequest {

    /**
     * The result of an authentication attempt.
     */
    public static enum Status {

        Success, Continue, Failure, None
    }

    /**
     * What to do with the previously authenticated users session.
     */
    public static enum ManageAction {

        None, Clear
    }

    /**
     * Get the context-path.
     * @return The context-path for the current request.
     */
    String getContextPath();

    /**
     * Get the HttpServletRequest for the current request.
     *
     * @return The HttpServletRequest instance for the current request.
     */
    HttpServletRequest getHttpServletRequest();

    /**
     * Get the HttpServletResponse for the current request.
     *
     * @return The HttpServletResponse instance for the current request.
     */
    HttpServletResponse getHttpServletResponse();

    /**
     * Get the HTTP-Parameter with given name.
     *
     * @param name The name of the parameter to return.
     * @return The value of the parameter.
     */
    String getParameter(String name);

    /**
     * Get a map containing all request attributes.
     * Changes to this map will be reflected in the request attributes.
     *
     * @return A map representing all request attributes.
     */
    Map<String, Object> getRequestMap();

    /**
     * Get the request-path.
     * @return Get the complete path of the current request, starting after
     * the context-path and excluding any parameters.
     */
    String getRequestPath();

    /**
     * Get the ServletContext for the current request.
     *
     * @return The ServletContext instance for the current request.
     */
    ServletContext getServletContext();

    /**
     * Get a map containing all session attributes.
     * Changes to this map will be reflected in the session attributes.
     *
     * @return A map representing all session attributes.
     */
    Map<String, Object> getSessionMap();

    /**
     * Get a map containing all application attributes.
     * Changes to this map will be reflected in the application attributes.
     *
     * @return A map representing all application attributes.
     */
    Map<String, Object> getApplicationMap();

    /**
     * This map can be used to store values across authentication-requests.
     *
     * @return A map for storing authentication values.
     */
    Map<String, Object> getAuthenticationMap();

    /**
     * Get whether authentication is mandatory for the current request.
     * If authentication is not mandatory the authenticator can still return
     * Success to signal that the resource should be served anyways.
     *
     * @return If authentication is mandatory for the requested resource.
     */
    boolean isMandatory();

}
