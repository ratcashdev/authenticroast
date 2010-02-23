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

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.WeakHashMap;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


/**
 *
 * @author Aike J Sommer
 */
public class SuperSession {

    private static final String COOKIE_NAME = "ROAST_XCTX";

    private static final String IN_SESSION_NOTE = SuperSession.class.getName() + ".IN_SESSION";

    private static final String IN_REQUEST_NOTE = SuperSession.class.getName() + ".IN_REQUEST";

    private static final Map<String, WeakReference<SuperSession>> sessions =
            new HashMap<String, WeakReference<SuperSession>>();

    private static final Map<SuperSession, String> sessionKeys =
            new WeakHashMap<SuperSession, String>();

    private static final Random random = new Random();

    private static int accessCounter = 0;

    public static SuperSession self(HttpServletRequest request, HttpServletResponse response,
            boolean create) {
        {
            SuperSession result = (SuperSession) request.getAttribute(IN_REQUEST_NOTE);
            if (result != null) {
                return result;
            }
        }

        String key = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(COOKIE_NAME)) {
                    key = cookie.getValue();
                }
            }
        }
        if (key == null) {
            key = Long.toHexString(random.nextLong()) + Long.toHexString(random.nextLong());
            key = key.toUpperCase();

            Cookie cookie = new Cookie(COOKIE_NAME, key);
            cookie.setMaxAge(-1);
            cookie.setPath("/");
            response.addCookie(cookie);
        }
        WeakReference<SuperSession> ref = sessions.get(key);
        SuperSession result = ref == null ? null : ref.get();
        if (result == null && create) {
            result = new SuperSession();
            ref = new WeakReference<SuperSession>(result);

            sessions.put(key, ref);
            sessionKeys.put(result, key);
        }
        HttpSession session = request.getSession(create);
        if (session != null) {
            if (result != null) {
                session.setAttribute(IN_SESSION_NOTE, result);
                request.setAttribute(IN_REQUEST_NOTE, result);
            } else {
                session.removeAttribute(IN_SESSION_NOTE);
                request.removeAttribute(IN_REQUEST_NOTE);
            }
        }

        accessCounter++;
        if (accessCounter > 100) {
            sessions.keySet().retainAll(sessionKeys.values());
        }

        return result;
    }

    private Map<String, Object> attributes = new HashMap();

    public Map<String, Object> attributes() {
        return attributes;
    }

}
