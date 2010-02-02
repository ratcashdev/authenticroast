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

import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;

/**
 *
 * @author Aike J Sommer
 */
public abstract class TicketAuthenticator extends PluggableAuthenticator {

    public static final String TICKET_PARAM = "j_security_ticket";

    /**
     * This method checks the supplied credentials and returns true if they
     * are valid.
     * 
     * @param ticket The ticket from the request.
     * @return true if the ticket is valid.
     */
    protected abstract boolean checkTicket(AuthenticationManager manager, AuthenticationRequest request, String ticket);

    /**
     * Create a SimplePrincipal from the ticket given.
     * 
     * @param ticket The ticket from the request.
     * @return A SimplePrincipal instance representing the user.
     */
    protected abstract SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, String ticket);

    @Override
    public Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        String ticket = request.getParameter(TICKET_PARAM);
        if (ticket != null) {
            if (checkTicket(manager, request, ticket)) {
                manager.register(request, loadPrincipal(manager, request, ticket));
                return Status.Success;
            }

            return Status.Failure;
        }
        
        return Status.None;
    }

    @Override
    public Status authenticate(AuthenticationManager manager, AuthenticationRequest request) {
        return Status.None;
    }

    @Override
    public ManageAction manage(AuthenticationManager manager, AuthenticationRequest request) {
        return ManageAction.None;
    }
}
