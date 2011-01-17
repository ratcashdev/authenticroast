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
import java.util.Map;

/**
 * This class takes care of storing and restoring the original request, that
 * led to the authentication being started.
 * It is used internally only.
 *
 * @author Aike J Sommer
 */
public class RequestHandler {

    private static final String REQUEST_CONTEXT_NOTE = RequestHandler.class.getName() + ".REQUEST_CONTEXT";
    private static final String REQUEST_PATH_NOTE = RequestHandler.class.getName() + ".REQUEST_PATH";
    private static final String REQUEST_QUERY_NOTE = RequestHandler.class.getName() + ".REQUEST_QUERY";
    private static final String REQUEST_ADD_QUERY_NOTE = RequestHandler.class.getName() + ".REQUEST_ADD_QUERY";

    private Map<String, Object> session(AuthenticationRequest request) {
        return request.getAuthenticationMap();
    }

    public void saveRequest(ModifiableRequest request) {
        session(request).put(REQUEST_CONTEXT_NOTE, request.getOriginalContext().getContextPath());
        session(request).put(REQUEST_PATH_NOTE, request.getRequestPath());
        session(request).put(REQUEST_QUERY_NOTE, request.getHttpServletRequest().getQueryString());
    }

    public void saveRequest(ModifiableRequest request, String path) {
        session(request).put(REQUEST_CONTEXT_NOTE, request.getOriginalContext().getContextPath());
        session(request).put(REQUEST_PATH_NOTE, path);
        session(request).put(REQUEST_QUERY_NOTE, "");
    }

    public void clearRequest(AuthenticationRequest request) {
        session(request).remove(REQUEST_CONTEXT_NOTE);
        session(request).remove(REQUEST_PATH_NOTE);
        session(request).remove(REQUEST_QUERY_NOTE);
    }

    public String getContextForRequest(AuthenticationRequest request) {
        String context = (String) session(request).get(REQUEST_CONTEXT_NOTE);
        return context;
    }

    public String getPathForRequest(AuthenticationRequest request) {
        String path = (String) session(request).get(REQUEST_PATH_NOTE);
        String query = (String) session(request).get(REQUEST_QUERY_NOTE);

        List<String> addQuery = (List<String>) session(request).get(REQUEST_ADD_QUERY_NOTE);
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

    public boolean matchesRequest(ModifiableRequest request) {
        String originalPath = (String) session(request).get(REQUEST_PATH_NOTE);
        String path = request.getRequestPath();
        String originalContext = (String) session(request).get(REQUEST_CONTEXT_NOTE);
        String context = request.getOriginalContext().getContextPath();

        if (originalPath != null && originalContext != null) {
            return path.equals(originalPath) && context.equals(originalContext);
        }

        return false;
    }

    public void restoreRequest(AuthenticationRequest request) {
        clearRequest(request);
    }

    public void addQueryString(AuthenticationRequest request, String queryString) {
        List<String> addQuery = (List) session(request).get(REQUEST_ADD_QUERY_NOTE);
        if (addQuery == null) {
            addQuery = new ArrayList<String>();
            session(request).put(REQUEST_ADD_QUERY_NOTE, addQuery);
        }
        addQuery.add(queryString);
    }

}
