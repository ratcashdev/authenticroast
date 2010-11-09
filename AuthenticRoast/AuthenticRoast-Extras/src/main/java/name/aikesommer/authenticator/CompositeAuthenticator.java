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
public abstract class CompositeAuthenticator extends PluggableAuthenticator {

    private volatile Collection<PluggableAuthenticator> authenticators = null;

    public CompositeAuthenticator() {
    }

    /**
     * Overwrite this to create the authenticators when they are first needed.
     * This will only be called once per instance.
     */
    protected abstract Collection<PluggableAuthenticator> createAuthenticators();

    /**
     * Returns the currently stored authenticators in this instance.
     *
     * @return The currently stored authenticators in this instance or null if
     *         they have not been created yet.
     */
    protected final Collection<PluggableAuthenticator> getAuthenticators() {
        return authenticators;
    }

    /**
     * Set the authenticators to be used by this instance.
     *
     * @param authenticators the authenticators to be used by this instance or
     *                       null to have <code>createAuthenticators()</code>
     *                       called next time they are needed.
     */
    protected final void setAuthenticators(Collection<PluggableAuthenticator> authenticators) {
        this.authenticators = authenticators;
    }

    /**
     * Get the list of authenticators to be used for this instance. The default
     * implementation will call <code>checkAuthenticators()</code> if
     * <code>authenticators</code> is <code>null</code> and then just return
     * the contents of <code>authenticators</code>.
     *
     * @param manager The {@link AuthenticationManager} used for this request.
     * @param request The {@link AuthenticationRequest} representing this request.
     * @return The list of authenticators.
     */
    protected Collection<PluggableAuthenticator> getAuthenticators(
            AuthenticationManager manager, AuthenticationRequest request) {
        if (authenticators == null) {
            synchronized (this) {
                if (authenticators == null) {
                    authenticators = createAuthenticators();
                }
            }
        }
        return authenticators;
    }

    @Override
    public Status tryAuthenticate(AuthenticationManager manager,
            AuthenticationRequest request) {
        for (PluggableAuthenticator authenticator : getAuthenticators(manager,
                request)) {
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
                request)) {
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
                request)) {
            ManageAction action = authenticator.manage(manager, request);
            if (action != null && action != ManageAction.None) {
                return action;
            }
        }

        return ManageAction.None;
    }
}
