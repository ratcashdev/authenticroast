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
import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 *
 * @author Aike J Sommer
 */
public abstract class WrappedRequest implements ModifiableRequest {

    private ServletContext context;

    public WrappedRequest(ServletContext context) {
        this.context = context;
    }

    protected abstract ModifiableRequest request();

    public String getContextPath() {
        return context.getContextPath();
    }

    public HttpServletRequest getHttpServletRequest() {
        return request().getHttpServletRequest();
    }

    public HttpServletResponse getHttpServletResponse() {
        return request().getHttpServletResponse();
    }

    public String getParameter(String name) {
        return request().getParameter(name);
    }

    public Map<String, Object> getRequestMap() {
        return request().getRequestMap();
    }

    public String getRequestPath() {
        return request().getRequestPath();
    }

    public ServletContext getServletContext() {
        return context;
    }

    public Map<String, Object> getSessionMap() {
        return request().getSessionMap();
    }

    public boolean isMandatory() {
        return request().isMandatory();
    }

    public boolean isForwarded() {
        return request().isForwarded();
    }

    public void setForwarded(boolean b) {
        request().setForwarded(b);
    }

    public boolean isCrossContext() {
        return true;
    }

    public void setCrossContext(boolean b) {
    }

    public ServletContext getOriginalContext() {
        return request().getServletContext();
    }

    public Map<String, Object> getApplicationMap() {
        return request().getApplicationMap();
    }

    public Map<String, Object> getAuthenticationMap() {
        return request().getAuthenticationMap();
    }

    public static class JSR196 extends WrappedRequest implements JSR196Request {

        private JSR196Request request;

        public JSR196(ServletContext context, JSR196Request request) {
            super(context);
            this.request = request;
        }

        @Override
        protected ModifiableRequest request() {
            return request;
        }

        public Subject getClientSubject() {
            return request.getClientSubject();
        }

    }
}
