/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package name.aikesommer.authenticator.test;

import name.aikesommer.authenticator.AuthenticationRequest;
import name.aikesommer.authenticator.FormAuthenticator;
import name.aikesommer.authenticator.PluggableAuthenticator.AuthenticationManager;
import name.aikesommer.authenticator.SimplePrincipal;

/**
 *
 * @author Aike J Sommer
 */
public class TestAuthenticator extends FormAuthenticator {

    @Override
    protected boolean checkCredentials(AuthenticationManager manager, AuthenticationRequest request, String username, String password) {
        return "test".equals(username) && "test".equals(password);
    }

    @Override
    protected SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, String username) {
        return new SimplePrincipal(username, "user");
    }

}
