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

import java.util.ArrayList;
import java.util.List;

/**
 * This class takes care of storing and restoring the original request, that
 * led to the authentication being started.
 * It is used internally only.
 *
 * @author Aike J Sommer
 */
public class RequestHandler {

    private static final String REQUEST_PATH_NOTE = "name.aikesommer.Authenticator.REQUEST_PATH";
    private static final String REQUEST_QUERY_NOTE = "name.aikesommer.Authenticator.REQUEST_QUERY";
    private static final String REQUEST_ADD_QUERY_NOTE = "name.aikesommer.Authenticator.REQUEST_ADD_QUERY";

    public void saveRequest(AuthenticationRequest request) {
        request.getSessionMap().put(REQUEST_PATH_NOTE, request.getRequestPath());
        request.getSessionMap().put(REQUEST_QUERY_NOTE, request.getHttpServletRequest().getQueryString());
    }

    public void clearRequest(AuthenticationRequest request) {
        request.getSessionMap().remove(REQUEST_PATH_NOTE);
        request.getSessionMap().remove(REQUEST_QUERY_NOTE);
    }

    public String getPathForRequest(AuthenticationRequest request) {
        String path = (String) request.getSessionMap().get(REQUEST_PATH_NOTE);
        String query = (String) request.getSessionMap().get(REQUEST_QUERY_NOTE);

        List<String> addQuery = (List<String>) request.getSessionMap().get(REQUEST_ADD_QUERY_NOTE);
        if (addQuery != null) {
            for (String q : addQuery) {
                query = query == null ? q : (query + "&" + q);
            }
        }

        if (path != null) {
            return path + (query == null ? "" : ("?" + query));
        }
        return null;
    }

    public boolean matchesRequest(AuthenticationRequest request) {
        String originalPath = (String) request.getSessionMap().get(REQUEST_PATH_NOTE);
        String path = request.getRequestPath();

        if (originalPath != null) {
            return path.equals(originalPath);
        }

        return false;
    }

    public void restoreRequest(AuthenticationRequest request) {
        clearRequest(request);
    }

    public void addQueryString(AuthenticationRequest request, String queryString) {
        List<String> addQuery = (List) request.getSessionMap().get(REQUEST_ADD_QUERY_NOTE);
        if (addQuery == null) {
            addQuery = new ArrayList<String>();
            request.getSessionMap().put(REQUEST_ADD_QUERY_NOTE, addQuery);
        }
        addQuery.add(queryString);
    }

}
