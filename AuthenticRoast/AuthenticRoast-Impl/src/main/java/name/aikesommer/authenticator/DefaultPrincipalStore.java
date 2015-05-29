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

import java.io.Serializable;
import javax.enterprise.context.SessionScoped;

/**
 * This is the default principal-store, which will store principals in the
 * current http-session.
 *
 * @author Aike J Sommer
 */
@SessionScoped
public class DefaultPrincipalStore implements PrincipalStore, Serializable {
	private static final long serialVersionUID = -6118361516136654899L;
	
	SimplePrincipal principal;

	@Override
    public void store(SimplePrincipal principal) {
        this.principal = principal;
    }

	@Override
    public SimplePrincipal fetch() {
        return principal;
    }

	@Override
    public void invalidate() {
        principal = null;
    }

}
