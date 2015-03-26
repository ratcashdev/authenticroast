# Introduction #

AuthenticRoast? needs a base module to be registered with the web-container. In the case of Glassfish this is a JSR-196 compatible authenticator.


# Preparing Glassfish #

First you need to copy the API and Impl JARs into the lib/ folder of your Glassfish installation. Now (re)start Glassfish.

Open the Glassfish admin-interface. Go to "Configuration" -> "Security" -> "Message security". Click on "New...". Enter the following values:

  * Authentication Layer: HttpServlet
  * Default Provider: no
  * Provider Type: server
  * Provider ID: roast
  * Class Name: name.aikesommer.authenticator.AuthModule

Save, go to "Configuration" -> "Security" -> "Message security" -> "HttpServlet" -> "Providers" and select "roast". Under "Request policy" enter:

  * Authenticate Source: sender
  * Authenticate Recipient: before-content

Leave "Response policy" empty.

Save and restart Glassfish.


# Selecting the provider in your web-app #

You will need to create or modify your sun-web.xml for this. Modify the top-level 

&lt;sun-web-app /&gt;

 element like this:
<sun-web-app httpservlet-security-provider="roast">
    ...
</sun-web-app>

You should now be ready to go!```