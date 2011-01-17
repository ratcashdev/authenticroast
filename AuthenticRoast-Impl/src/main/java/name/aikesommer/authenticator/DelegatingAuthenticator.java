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

import javax.servlet.ServletContext;


public class DelegatingAuthenticator extends PluggableAuthenticator {

    private PluggableAuthenticator delegateAuthenticator;

    private ServletContext delegateContext;

    public DelegatingAuthenticator(PluggableAuthenticator delegateAuthenticator,
            ServletContext delegateContext) {
        this.delegateAuthenticator = delegateAuthenticator;
        this.delegateContext = delegateContext;
    }

    private AuthenticationRequest wrapRequest(AuthenticationRequest request) {
        return ((AuthenticationRequestImpl) request).delegate(delegateContext);
    }

    @Override
    public AuthenticationRequest.Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        return delegateAuthenticator.tryAuthenticate(manager, wrapRequest(request));
    }

    @Override
    public AuthenticationRequest.Status authenticate(AuthenticationManager manager, AuthenticationRequest request) {
        return delegateAuthenticator.authenticate(manager, wrapRequest(request));
    }

    @Override
    public AuthenticationRequest.ManageAction manage(AuthenticationManager manager, AuthenticationRequest request) {
        return delegateAuthenticator.manage(manager, wrapRequest(request));
    }

}
