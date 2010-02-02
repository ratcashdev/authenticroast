/**
 *    Copyright (C) 2007-2010 Aike J Sommer (http://aikesommer.name/)
 *
 *    This file is part of AuthenticRoast.
 *
 *    This file is just a sample. You are free to use and modify the
 *    code in this file to your liking!
 *
 *    This file is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *    You can reach the author and get more information about this
 *    project at: http://aikesommer.name/
 */
package name.aikesommer.authenticator.samples;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import name.aikesommer.authenticator.AuthenticationRequest;
import name.aikesommer.authenticator.DelegatingAuthenticator;
import name.aikesommer.authenticator.FormAuthenticator;
import name.aikesommer.authenticator.LogoutManager;
import name.aikesommer.authenticator.PluggableAuthenticator;
import name.aikesommer.authenticator.SimplePrincipal;
import name.aikesommer.authenticator.TicketAuthenticator;

/**
 * This is just a sample, make sure to actually check credentials and such!!
 * 
 * @author Aike J Sommer
 */
public class FormAndTicketSample extends DelegatingAuthenticator {

    @Override
    protected Collection<PluggableAuthenticator> createAuthenticators() {
        List<PluggableAuthenticator> result = new ArrayList();
        
        /**
         * Allow form-based logins.
         */
        result.add(new FormAuthenticator() {

            @Override
            protected boolean checkCredentials(AuthenticationManager manager, AuthenticationRequest request, String username, String password) {
                // check the credentials with some config-files, db-data
                // or a realm in the app-server
                
                // we just return true here, so everything will be accepted
                return true;
            }

            @Override
            protected SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, String username) {
                // load user-data from config-files, db or where ever you
                // have it stored :-)
                
                return new SimplePrincipal(username, "user");
            }
        });
        
        /**
         * Allow ticket-based logins.
         */
        result.add(new TicketAuthenticator() {

            @Override
            protected boolean checkTicket(AuthenticationManager manager, AuthenticationRequest request, String ticket) {
                // check the ticket, for example with some secret and a 
                // hash
                
                // we just return true here, so everything will be accepted
                return true;
            }

            @Override
            protected SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, String ticket) {
                return new SimplePrincipal("guest", "guest");
            }
        });
        
        /**
         * Allow a user to "logout".
         */
        result.add(new LogoutManager());
        
        return result;
    }

}
