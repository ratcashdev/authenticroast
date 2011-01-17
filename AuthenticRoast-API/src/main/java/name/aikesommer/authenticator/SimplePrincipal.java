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

import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * A very simple approach to returning a principal together with its 
 * group-information. You can subclass this if u wanna store more information
 * for ur principal.
 * 
 * @author Aike J Sommer
 */
public class SimplePrincipal implements Principal {

    /**
     * Use this to access the current authenticated principal, if you need
     * access to any of the information in your sub-class.
     *
     * @deprecated
     * @param session The current session as in HttpServletRequest.getSession()
     * @return The previously authenticated SimplePrincipal instance for this
     *         session.
     */
    public static SimplePrincipal getPrincipal(HttpSession session) {
        return Registry.forContext(session.getServletContext()).principalStore().fetch();
    }

    /**
     * Use this to access the current authenticated principal, if you need
     * access to any of the information in your sub-class.
     *
     * @param request The current HttpServletRequest
     * @return The previously authenticated SimplePrincipal instance for this
     *         session.
     */
    public static SimplePrincipal getPrincipal(HttpServletRequest request) {
        return Registry.forContext(request.getSession().getServletContext()).principalStore().fetch();
    }

    /**
     * Use this to store an authenticated principal from within your application.
     *
     * @param request The current HttpServletRequest
     * @param principal The authenticated SimplePrincipal
     */
    public static void setPrincipal(HttpServletRequest request, SimplePrincipal principal) {
        Registry.forContext(request.getSession().getServletContext()).principalStore().store(principal);
    }

    
    private String name;
    private Set<String> groups = new HashSet();

    /**
     * Create a SimplePrincipal with username and groups.
     * 
     * @param name The username of the principal.
     * @param groups The groups this principal belongs to.
     */
    public SimplePrincipal(String name, String ... groups) {
        this.name = name;
        for (int i = 0; i < groups.length; i++) {
            String group = groups[i];
            this.groups.add(group);
        }
    }
    
    public String getName() {
        return name;
    }

    /**
     * Return a collection of all groups this principal belongs to.
     * 
     * @return A collection of all groups this principal belongs to.
     */
    public Collection<String> getGroups() {
        return groups;
    }

    @Override
    public String toString() {
        String result = null;
        for (String group : groups) {
            result = (result == null ? group : (result + ", " + group));
        }

        return name + " (" + result + ")";
    }

}
