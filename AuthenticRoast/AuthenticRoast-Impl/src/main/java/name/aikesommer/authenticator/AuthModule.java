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
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.util.AnnotationLiteral;
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
public abstract class AuthModule extends AuthenticationManagerBase implements ServerAuthModule,
        PluggableAuthenticator.AuthenticationManager {

    private CallbackHandler handler;

    private Map options;

    private MessagePolicy responsePolicy;

    private MessagePolicy requestPolicy;

    private boolean success;

	@Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
            CallbackHandler handler, Map options) throws AuthException {
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.handler = handler;
        this.options = options;
        this.success = false;
    }

	@Override
    public Class[] getSupportedMessageTypes() {
        return null;
    }
	
	/**
	 * Retrieves the BeanManager associated with the current ServletContext and then a reference to an @ApplicationScoped
	 * PluggableAuthenticator.
	 * @return 
	 */
	protected abstract PluggableAuthenticator getPrimaryAuthenticator();
//	{
//		return CDIHelper.getInstance(PluggableAuthenticator.class, ApplicationScoped.class, new AnnotationLiteral<Primary>() {});
//		return CDIHelper.getReferenceOrNull(PluggableAuthenticator.class, new AnnotationLiteral<Primary>() {});
//	}
	
	@Override
	public AuthStatus validateRequest(MessageInfo info, Subject clientSubject, Subject serviceSubject) throws AuthException {
		
//		Instance<PluggableAuthenticator> authInstance = CDIHelper.getCdiAuthenticator();
		
//		BeanManager beanManager = CDIHelper.getBeanManager();
//		Bean<PluggableAuthenticator> bean = (Bean<PluggableAuthenticator>) beanManager.resolve(beanManager.getBeans(PluggableAuthenticator.class, new AnnotationLiteral<Primary>() {}));
//		CreationalContext ctx = beanManager.createCreationalContext(bean);
//		PluggableAuthenticator authenticator = (PluggableAuthenticator) beanManager.getReference(bean, PluggableAuthenticator.class, ctx);
		
		System.out.println("Retrieving main CDI bean.");
		PluggableAuthenticator authenticator = getPrimaryAuthenticator();
		System.out.println("Retrieved: " + authenticator);
		
        /**
         * Find the authenticator for this application.
         */
//		authenticator = authInstance.get();
//		if(authenticator == null) {
////			System.out.println("Resetting instance.");
////			authInstance = null;
//			System.out.println("Authenticator is null. Trying manual lookup.");
//			authenticator = registry.authenticator();
//		}
		
		AuthStatus result = AuthStatus.FAILURE;
		// Reject requests, if there's no authenticator defined
		if(authenticator != null) {
			result = requestValidator(info, clientSubject, serviceSubject, authenticator);
		}
		
//		if(authInstance != null) {
//			System.out.println("Destroying.");
//			authInstance.destroy(authenticator);
//		}
		
//		bean.destroy(authenticator, ctx);
//		 ctx.release();
		return result;
	}
	
	
    protected AuthStatus requestValidator(MessageInfo info, Subject clientSubject,
            Subject serviceSubject, PluggableAuthenticator authenticator) throws AuthException {
		
        HttpServletRequest request = (HttpServletRequest) info.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) info.getResponseMessage();

		boolean mandatory = true;
//		mandatory = requestPolicy.isMandatory();
        JSR196Request authReq = new AuthenticationRequestImpl.JSR196(request, response,
                clientSubject, mandatory);

        boolean finished = false;
        try {
            authenticator.begin(this, authReq);

            /**
             * Check whether we already authenticated the user. In that case we
             * saved our Principal in the session and can just load it from 
             * there.
             * We will call manage() in our authenticator to be able to logout
             * and such things.
             */
            SimplePrincipal simplePrincipal = getPrincipalStore().fetch();
            if (simplePrincipal != null) {
                ManageAction action = authenticator.manage(this, authReq);
                switch (action) {
                    case None:
                        createPrincipal(simplePrincipal, clientSubject);
                        success = true;
                        return AuthStatus.SUCCESS;
                    case Clear:
                        getPrincipalStore().invalidate();
                        return AuthStatus.SEND_CONTINUE;
                }
            }

            /**
             * The user hasn't been authenticated before, so we'll try to do
             * that now. The actual process of authentication will be done 
             * by the authenticator class in our web-app.
             */
            Status status = authenticator.tryAuthenticate(this, authReq);

            switch (status) {
                case Success:
                    success = true;
                    return AuthStatus.SUCCESS;
                case None:
                    if (!mandatory) {
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

	@Override
    public AuthStatus secureResponse(MessageInfo info, Subject serviceSubject) throws AuthException {
        return success ? AuthStatus.SEND_SUCCESS : AuthStatus.SEND_CONTINUE;
    }

	@Override
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
