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

import java.util.Collection;
import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;

/**
 * This class allows for easy combination of different Authenticators,
 * for example to allow a combination of ticket- and form-login.
 * Just implement getAuthenticators() and return the authenticators you
 * want to use. If you need a specific order in which they are used
 * make sure to return a list and not a set or similar.
 * 
 * @author Aike J Sommer
 */
public abstract class DelegatingAuthenticator extends PluggableAuthenticator {

    private Collection<PluggableAuthenticator> authenticators;

    public DelegatingAuthenticator() {
        authenticators = createAuthenticators();
    }

    protected abstract Collection<PluggableAuthenticator> createAuthenticators();

    protected Collection<PluggableAuthenticator> getAuthenticators(
            AuthenticationManager manager, AuthenticationRequest request,
            Collection<PluggableAuthenticator> authenticators) {
        return authenticators;
    }

    protected Collection<PluggableAuthenticator> getAuthenticators(
            AuthenticationManager manager, AuthenticationRequest request) {
        return getAuthenticators(manager, request, authenticators);
    }

    @Override
    public Status tryAuthenticate(AuthenticationManager manager,
            AuthenticationRequest request) {
        for (PluggableAuthenticator authenticator : getAuthenticators(manager,
                request, authenticators)) {
            Status status = authenticator.tryAuthenticate(manager, request);
            if (status != null && status != Status.None) {
                return status;
            }
        }

        return Status.None;
    }

    @Override
    public Status authenticate(AuthenticationManager manager,
            AuthenticationRequest request) {
        for (PluggableAuthenticator authenticator : getAuthenticators(manager,
                request, authenticators)) {
            Status status = authenticator.authenticate(manager, request);
            if (status != null && status != Status.None) {
                return status;
            }
        }

        return Status.None;
    }

    @Override
    public ManageAction manage(AuthenticationManager manager,
            AuthenticationRequest request) {
        for (PluggableAuthenticator authenticator : getAuthenticators(manager,
                request, authenticators)) {
            ManageAction action = authenticator.manage(manager, request);
            if (action != null && action != ManageAction.None) {
                return action;
            }
        }

        return ManageAction.None;
    }
}
