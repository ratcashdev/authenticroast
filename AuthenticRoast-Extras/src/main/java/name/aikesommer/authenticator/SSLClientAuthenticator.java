/*
 *    Copyright (c) Verismart Software Inc and Esmond Pitt, 2010.
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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import name.aikesommer.authenticator.AuthenticationRequest.ManageAction;
import name.aikesommer.authenticator.AuthenticationRequest.Status;

/**
 * SSL Client Certificate authentication base class.
 *
 * @author Esmond Pitt
 */
public abstract class SSLClientAuthenticator extends PluggableAuthenticator
{
    /**
     * Check SSL client credentials.
     * Derived classes must implement this method.
     * @param am AuthenticationManager
     * @param ar AuthenticationReqeust
     * @param certs Certificate chain:
     * the first entry is the client cert, the others are signing certs;
     * SSL should already have verified the chain,
     * so the only thing of interest really is certs[0].getSubjectX500Principal(),
     * which should correspond (somehow) to a known user in your realm.
     * @return true on success.
     */
    protected abstract boolean checkCredentials(AuthenticationManager manager, AuthenticationRequest request, X509Certificate[] certs);

    /**
     * Create a SimplePrincipal from the certificate sent by the client.
     * Derived classes must implement this method.
     *
     * @param am AuthenticationManager
     * @param ar AuthenticationReqeust
     * @param certs Certificate chain:
     * the first entry is the client cert, the others are signing certs;
     * SSL should already have verified the chain,
     * so the only thing of interest really is certs[0].getSubjectX500Principal(),
     * which should correspond (somehow) to a known user in your realm.
     * @return A SimplePrincipal instance representing the user.
     */
    protected abstract SimplePrincipal loadPrincipal(AuthenticationManager manager, AuthenticationRequest request, X509Certificate[] certs);

    @Override
    public Status tryAuthenticate(AuthenticationManager manager, AuthenticationRequest request) {
        X509Certificate[]       certs = (X509Certificate[])request
                        .getHttpServletRequest()
                        .getAttribute("javax.servlet.request.X509Certificate");
        if (certs != null) {
            if (checkCredentials(manager, request, certs)) {
                manager.register(request, loadPrincipal(manager, request, certs));
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
