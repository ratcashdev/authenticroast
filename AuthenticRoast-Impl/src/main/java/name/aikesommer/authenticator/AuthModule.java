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

import java.io.IOException;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;


/**
 * This is the main class called by the container. You probably dont wanna
 * call this class directly.
 * 
 * @author Aike J Sommer
 */
public class AuthModule extends AuthenticationManagerBase implements ServerAuthModule,
        PluggableAuthenticator.AuthenticationManager {

    private CallbackHandler handler;

    private Map options;

    private MessagePolicy responsePolicy;

    private MessagePolicy requestPolicy;

    private boolean success;

    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
            CallbackHandler handler, Map options) throws AuthException {
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.handler = handler;
        this.options = options;
        this.success = false;
    }

    public Class[] getSupportedMessageTypes() {
        return null;
    }

    public AuthStatus validateRequest(MessageInfo info, Subject clientSubject,
            Subject serviceSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) info.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) info.getResponseMessage();
        ServletContext context = request.getSession().getServletContext();
        RegistryImpl registry = RegistryImpl.forContext(context);

        JSR196Request authReq = new AuthenticationRequestImpl.JSR196(request, response,
                clientSubject, requestPolicy.isMandatory(), registry.isCrossContext());
        registry.createPrincipalStore(authReq);

        /**
         * Find the authenticator for this application.
         */
        PluggableAuthenticator authenticator = registry.authenticator();

        boolean finished = false;
        try {
            authenticator.begin(this, authReq);

            /**
             * Check wether we already authenticated the user. In that case we
             * saved our Principal in the session and can just load it from 
             * there.
             * We will call manage() in our authenticator to be able to logout
             * and such things.
             */
            SimplePrincipal simplePrincipal = registry.principalStore().fetch();
            if (simplePrincipal != null) {
                ManageAction action = authenticator.manage(this, authReq);
                switch (action) {
                    case None:
                        createPrincipal(simplePrincipal, clientSubject);
                        success = true;
                        return AuthStatus.SUCCESS;
                    case Clear:
                        registry.principalStore().invalidate();
                        return AuthStatus.SEND_CONTINUE;
                }
            }

            /**
             * The user hasnt been authenticated before, so we'll try to do
             * that now. The actual process of authentication will be done 
             * by the authenticator class in our web-app.
             */
            Status status = authenticator.tryAuthenticate(this, authReq);

            switch (status) {
                case Success:
                    success = true;
                    return AuthStatus.SUCCESS;
                case None:
                    if (!requestPolicy.isMandatory()) {
                        success = true;
                        return AuthStatus.SUCCESS;
                    }
                    status = authenticator.authenticate(this, authReq);
                    if (status == Status.Success) {
                        success = true;
                        return AuthStatus.SUCCESS;
                    }
                case Continue:
                case Failure:
                    response.setStatus(response.SC_UNAUTHORIZED);
                    return AuthStatus.SEND_CONTINUE;
                default:
                    throw new IllegalArgumentException("dont know how to handle " + status);
            }
        } catch (Exception ex) {
            finished = true;
            authenticator.abort(this, authReq, ex);
            ex.printStackTrace();
            try {
                response.sendError(response.SC_INTERNAL_SERVER_ERROR, ex.getMessage());
            } catch (IOException ex1) {
                ex1.printStackTrace();
            }

            return AuthStatus.FAILURE;
        } finally {
            if (!finished) {
                authenticator.finish(this, authReq);
            }
        }
    }

    public AuthStatus secureResponse(MessageInfo info, Subject serviceSubject) throws AuthException {
        return success ? AuthStatus.SEND_SUCCESS : AuthStatus.SEND_CONTINUE;
    }

    public void cleanSubject(MessageInfo info, Subject subject) throws AuthException {
    }

    /**
     * This is just to create the principal as needed by jsr 196 from our little
     * helper-class SimplePrincipal.
     * 
     * @param simplePrincipal The SimplePrincipal representing the authenticated
     *          user.
     */
    private void createPrincipal(SimplePrincipal simplePrincipal, Subject clientSubject) throws
            IOException, UnsupportedCallbackException {
        clientSubject.getPrincipals().add(simplePrincipal);

        CallerPrincipalCallback callerCallback = new CallerPrincipalCallback(clientSubject,
                simplePrincipal);
        GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, simplePrincipal.getGroups().toArray(
                new String[0]));

        handler.handle(new Callback[]{callerCallback, groupCallback});
    }

    @Override
    public void register(AuthenticationRequest request, SimplePrincipal simplePrincipal) {
        try {
            createPrincipal(simplePrincipal, ((JSR196Request) request).getClientSubject());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        super.register(request, simplePrincipal);
    }

}
