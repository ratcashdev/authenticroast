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
 * This is the class that has to be implemented and registered for authentication
 * to work.
 * 
 * @author Aike J Sommer
 */
public abstract class PluggableAuthenticator {

    /**
     * This method will be called prior to any of the actual authentication
     * or management methods.
     *
     * @param manager The AuthenticationManager that allows for access
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     */
    public void begin(AuthenticationManager manager, AuthenticationRequest request) {
    }

    /**
     * This method will be called after the process has been completed.
     * It will not be called in the case of an exception though.
     *
     * @param manager The AuthenticationManager that allows for access
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     */
    public void finish(AuthenticationManager manager, AuthenticationRequest request) {
    }

    /**
     * This method will be called in the case of an exception.
     *
     * @param manager The AuthenticationManager that allows for access
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     * @param cause The exception that caused the authentication process
     *              to be aborted.
     */
    public void abort(AuthenticationManager manager, AuthenticationRequest request, Throwable cause) {
    }

    /**
     * This method is called when an unauthenticated request is made, even
     * when the current request is for a "public" resource.
     * This method should return Status.None if no indication exists for the
     * user trying to login (eg special headers, parameters).
     * 
     * @param manager The AuthenticationManager that allows for access 
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     * @return Return what is supposed to happen after returning.
     *         Status.Success if authentication succeded, Status.None if no 
     *         action has been performed, Status.Continue if authentication 
     *         is in progress (eg forwarded to a login-page) or Status.Failure 
     *         if some error occured.
     */
    public abstract AuthenticationRequest.Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request);
    
    /**
     * This method is called when an unauthenticated request is made, the
     * requested resource requires authentication and tryAuthenticate 
     * returned Status.None.
     * 
     * @param manager The AuthenticationManager that allows for access 
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     * @return Return what is supposed to happen after returning.
     *         Status.Success if authentication succeded, Status.Continue if 
     *         authentication is in progress (eg forwarded to a login-page) or 
     *         Status.Failure if some error occured.
     */
    public abstract AuthenticationRequest.Status authenticate(AuthenticationManager manager, AuthenticationRequest request);
    
    /**
     * This method allows for managing user-session, such as logging a user out.
     * 
     * @param manager The AuthenticationManager that allows for access 
     *                to some common actions while doing authentication.
     * @param request The AuthenticationRequest encapsulating all data
     *                needed to perform authentication.
     * @return Return what is supposed to happen after returning.
     *         ManageAction.None if no change should happen or 
     *         ManageAction.Clear to "logout" the current principal.
     */
    public abstract AuthenticationRequest.ManageAction manage(AuthenticationManager manager, AuthenticationRequest request);

    
    /**
     * AuthenticationManager allows for access to some common actions while 
     * doing authentication.
     */
    public static interface AuthenticationManager {
        
        /**
         * Returns wether a request has been saved before.
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public boolean hasRequest(AuthenticationRequest request);

        /**
         * Save the current request, so that it can be restored after
         * successful authentication.
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public void saveRequest(AuthenticationRequest request);

        /**
         * Save the path as original request, so that it can be restored after
         * successful authentication.
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         * @param path The path to be used as original request.
         */
        public void saveRequest(AuthenticationRequest request, String path);

        /**
         * Redirect to a previously stored request with saveRequest.
         * 
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public void redirectToRequest(AuthenticationRequest request);
        
        /**
         * Restore a previously stored request with saveRequest, after 
         * redirecting to it with redirectToRequest.
         * 
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public void restoreRequest(AuthenticationRequest request);
        
        /**
         * Remove a previously stored request.
         * 
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public void clearRequest(AuthenticationRequest request);
        
        /**
         * Check wether this is the resubmit of a previuosly stored
         * request.
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public boolean matchesRequest(AuthenticationRequest request);

        /**
         * This allows you to append a query-string to the original request
         * when it is redirected to. This can be used to pass data to the
         * page that is accessed which is collected during the login-process
         * (language selection on the login-page, eg).
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         * @param queryString The query-string to be appended. This should not
         *                start or end with an &amp;, as that is automatically
         *                inserted where needed.
         */
        public void addQueryString(AuthenticationRequest request, String queryString);

        /**
         * Forward to the path, eg to forward to a login-page.
         *
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         * @param path The path to forward to.
         */
        public void forward(AuthenticationRequest request, String path);

        /**
         * Register a SimplePrincipal instance after successful authentication.
         * 
         * @param request The AuthenticationRequest encapsulating all data
         *                needed to perform authentication.
         */
        public void register(AuthenticationRequest request, SimplePrincipal principal);
        
    }

}
