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

/**
 * The PrincipalStore is used to store data for an authenticated user across
 * multiple requests. The default implementation stores the Principal in the
 * current HttpSession which is the expected behavior for most applications.
 * If however the Principal needs to be visible to a different scope, to
 * provide SSO across different web-apps for example, you can register a
 * custom instance to use.
 * This can be done with Registry.register() or the init-parameter
 * <code>roast.principal-store.factory</code>.
 *
 * @author Aike J Sommer
 */
public interface PrincipalStore {

    void store(SimplePrincipal principal);
    SimplePrincipal fetch();
    void invalidate();

    public static interface Factory {

        PrincipalStore factory(AuthenticationRequest request);

    }

}
