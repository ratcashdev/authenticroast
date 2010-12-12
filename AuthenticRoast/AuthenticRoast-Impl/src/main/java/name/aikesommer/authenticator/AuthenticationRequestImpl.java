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

import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

/**
 * The class representing the request for authentication to be passed to the
 * authenticator-object in aur web-app. This basically encapsulates some 
 * of the involved objects for simplicity.
 * 
 * @author Aike J Sommer
 */
public abstract class AuthenticationRequestImpl implements ModifiableRequest {

    private HttpServletResponse response;
    private HttpServletRequest request;
    private boolean mandatory;
    private boolean forwarded = false;
    private boolean crossContext;
    private Map<String, Object> authenticationMap;

    public AuthenticationRequestImpl(HttpServletRequest request, HttpServletResponse response,
            boolean mandatory, boolean crossContext) {
        this.request = request;
        this.response = response;
        this.mandatory = mandatory;
        this.crossContext = crossContext;
        this.authenticationMap = crossContext ? SuperSession.self(request, response, true).attributes()
                : getSessionMap();
    }

    protected abstract AuthenticationRequest delegate(ServletContext context);

    /**
     * Get the ServletContext for the current request.
     * 
     * @return The ServletContext instance for the current request.
     */
    public ServletContext getServletContext() {
        return request.getSession(true).getServletContext();
    }

    /**
     * Get the HttpServletRequest for the current request.
     * 
     * @return The HttpServletRequest instance for the current request.
     */
    public HttpServletRequest getHttpServletRequest() {
        return request;
    }

    /**
     * Get the HttpServletResponse for the current request.
     * 
     * @return The HttpServletResponse instance for the current request.
     */
    public HttpServletResponse getHttpServletResponse() {
        return response;
    }

    /**
     * Get the HTTP-Parameter with given name.
     * 
     * @param name The name of the parameter to return.
     * @return The value of the parameter.
     */
    public String getParameter(String name) {
        return request.getParameter(name);
    }

    /**
     * Get the request-path.
     * @return Get the complete path of the current request, starting after
     *          the context-path and excluding any parameters.
     */
    public String getRequestPath() {
        String requested = request.getRequestURI();
        if (! requested.startsWith(getContextPath())) {
            throw new IllegalArgumentException(requested);
        }
        return requested.substring(getContextPath().length());
    }

    /**
     * Get the context-path.
     * @return The context-path for the current request.
     */
    public String getContextPath() {
        return request.getContextPath();
    }

    public boolean isForwarded() {
        return forwarded;
    }

    public void setForwarded(boolean forwarded) {
        this.forwarded = forwarded;
    }

    public boolean isCrossContext() {
        return crossContext;
    }

    public void setCrossContext(boolean b) {
        crossContext = b;
    }

    /**
     * Get a map containing all session attributes.
     * Changes to this map will be reflected in the session attributes.
     * 
     * @return A map representing all session attributes.
     */
    public Map<String, Object> getSessionMap() {
        return new AttributeMap() {

            @Override
            public Enumeration<String> getAttributeNames() {
                return request.getSession(true).getAttributeNames();
            }

            @Override
            public Object getAttribute(String s) {
                return request.getSession(true).getAttribute(s);
            }

            @Override
            public void setAttribute(String s, Object o) {
                request.getSession(true).setAttribute(s, o);
            }

            @Override
            public void removeAttribute(String s) {
                request.getSession(true).removeAttribute(s);
            }
        };
    }

    /**
     * Get a map containing all request attributes.
     * Changes to this map will be reflected in the request attributes.
     * 
     * @return A map representing all request attributes.
     */
    public Map<String, Object> getRequestMap() {
        return new AttributeMap() {

            @Override
            public Enumeration<String> getAttributeNames() {
                return request.getAttributeNames();
            }

            @Override
            public Object getAttribute(String s) {
                return request.getAttribute(s);
            }

            @Override
            public void setAttribute(String s, Object o) {
                request.setAttribute(s, o);
            }

            @Override
            public void removeAttribute(String s) {
                request.removeAttribute(s);
            }
        };
    }

    public Map<String, Object> getApplicationMap() {
        final ServletContext context = getServletContext();
        return new AttributeMap() {

            @Override
            public Enumeration<String> getAttributeNames() {
                return context.getAttributeNames();
            }

            @Override
            public Object getAttribute(String s) {
                return context.getAttribute(s);
            }

            @Override
            public void setAttribute(String s, Object o) {
                context.setAttribute(s, o);
            }

            @Override
            public void removeAttribute(String s) {
                context.removeAttribute(s);
            }
        };
    }

    public Map<String, Object> getAuthenticationMap() {
        return authenticationMap;
    }

    /**
     * Get whether authentication is mandatory for the current request.
     * If authentication is not mandatory the authenticator can still return
     * Success to signal that the resource should be served anyways.
     * 
     * @return If authentication is mandatory for the requested resource.
     */
    public boolean isMandatory() {
        return mandatory;
    }

    /**
     * You dont need to call this and it should be hidden in an impl-class.
     * 
     * @param mandatory
     */
    public void setMandatory(boolean mandatory) {
        this.mandatory = mandatory;
    }

    public ServletContext getOriginalContext() {
        return getServletContext();
    }

    public static class JSR196 extends AuthenticationRequestImpl implements JSR196Request {

        private Subject clientSubject;

        public JSR196(HttpServletRequest request, HttpServletResponse response,
                Subject clientSubject, boolean mandatory, boolean crossContext) {
            super(request, response, mandatory, crossContext);
            this.clientSubject = clientSubject;
        }

        /**
         * Get the ClientSubject for the current request.
         * 
         * @return The ClientSubject instance for the current request.
         */
        public Subject getClientSubject() {
            return clientSubject;
        }

        @Override
        protected JSR196Request delegate(ServletContext context) {
            return new WrappedRequest.JSR196(context, this);
        }

    }

    public static class Tomcat6 extends AuthenticationRequestImpl implements Tomcat6Request {

        private Request catalinaRequest;
        private Response catalinaResponse;

        public Tomcat6(Request request, Response response, boolean mandatory, boolean crossContext) {
            super(request.getRequest(), response.getResponse(), mandatory, crossContext);
            this.catalinaRequest = request;
            this.catalinaResponse = response;
        }

        public Request getCatalinaRequest() {
            return catalinaRequest;
        }

        public Response getCatalinaResponse() {
            return catalinaResponse;
        }

        @Override
        protected Tomcat6Request delegate(ServletContext context) {
            return new WrappedRequest.Tomcat6(context, this);
        }

    }

    public abstract static class AttributeMap extends NoteMap {

        @Override
        public Iterator<String> getNoteNames() {
            return new Iterator<String>() {

                Enumeration<String> pos = getAttributeNames();
                String current = null;
                String last = null;

                public boolean hasNext() {
                    return pos.hasMoreElements();
                }

                public String next() {
                    last = current;
                    current = pos.nextElement();
                    return current;
                }

                public void remove() {
                    if (current == null) {
                        return;
                    }
                    String before = last;
                    removeAttribute(current);
                    if (before != null) {
                        while (hasNext() && !before.equals(next())) {
                        }
                    }
                }
            };
        }

        @Override
        public Object getNote(String s) {
            return getAttribute(s);
        }

        @Override
        public void setNote(String s, Object o) {
            setAttribute(s, o);
        }

        @Override
        public void removeNote(String s) {
            removeAttribute(s);
        }

        public abstract Enumeration<String> getAttributeNames();

        public abstract Object getAttribute(String s);

        public abstract void setAttribute(String s, Object o);

        public abstract void removeAttribute(String s);
    }

    public abstract static class NoteMap extends AbstractMap<String, Object> {

        public abstract Iterator<String> getNoteNames();

        public abstract Object getNote(String s);

        public abstract void setNote(String s, Object o);

        public abstract void removeNote(String s);

        @Override
        public Set<Entry<String, Object>> entrySet() {
            return new NoteEntrySet(this);
        }

        @Override
        public int size() {
            int count = 0;
            for (Iterator<String> it = getNoteNames(); it.hasNext();) {
                it.next();
                count++;
            }

            return count;
        }

        @Override
        public Object get(Object key) {
            if (!(key instanceof String)) {
                return null;
            }
            return getNote((String) key);
        }

        @Override
        public boolean containsKey(Object key) {
            if (!(key instanceof String)) {
                return false;
            }

            String keyStr = (String) key;
            if (get(keyStr) != null) {
                return true;
            }

            for (Iterator<String> it = getNoteNames(); it.hasNext();) {
                String name = it.next();
                if (name.equals(keyStr)) {
                    return true;
                }
            }

            return false;
        }

        @Override
        public boolean isEmpty() {
            return !getNoteNames().hasNext();
        }

        @Override
        public Set<String> keySet() {
            return new NoteKeySet(this);
        }

        @Override
        public void clear() {
            for (Iterator<String> it = keySet().iterator(); it.hasNext();) {
                it.remove();
            }
        }

        @Override
        public Object put(String key, Object value) {
            Object old = get(key);
            setNote(key, value);
            return old;
        }

        @Override
        public Object remove(Object key) {
            if (!(key instanceof String)) {
                return null;
            }

            String keyStr = (String) key;
            Object old = get(keyStr);
            removeNote(keyStr);
            return old;
        }
    }

    public static class NoteKeySet extends AbstractSet<String> {

        private NoteMap map;

        public NoteKeySet(NoteMap map) {
            this.map = map;
        }

        @Override
        public Iterator<String> iterator() {
            return new Iterator<String>() {

                private String current = null;
                private Iterator<String> pos = map.getNoteNames();

                public boolean hasNext() {
                    return pos.hasNext();
                }

                public String next() {
                    current = pos.next();
                    return current;
                }

                public void remove() {
                    pos.remove();
                }
            };
        }

        @Override
        public int size() {
            return map.size();
        }
    }

    public static class NoteEntrySet extends AbstractSet<Map.Entry<String, Object>> {

        private NoteMap map;

        public NoteEntrySet(NoteMap map) {
            this.map = map;
        }

        @Override
        public Iterator<Map.Entry<String, Object>> iterator() {
            return new Iterator<Map.Entry<String, Object>>() {

                private Iterator<String> it = map.keySet().iterator();

                public boolean hasNext() {
                    return it.hasNext();
                }

                public Map.Entry<String, Object> next() {
                    return new Map.Entry() {

                        private String key = it.next();

                        public Object getKey() {
                            return key;
                        }

                        public Object getValue() {
                            return map.get(key);
                        }

                        public Object setValue(Object value) {
                            return map.put(key, value);
                        }
                    };
                }

                public void remove() {
                    it.remove();
                }
            };
        }

        @Override
        public int size() {
            return map.size();
        }
    }
}
