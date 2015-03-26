**AuthenticRoast** allows you to build highly flexible authentication mechanisms for the Java Web tier. This can be anything from HTTP Basic authentication to authenticating with openid, facebook, or your company's Kerberos setup. The authentication modules can be combined at will and even changed at runtime.

This currently works for Glassfish and plain Tomcat and allows you to use all the features of container-managed security without being constrained to the simple login methods provided.

It is partly based on JSR-196.

# Who is this for? #

This is intended for anybody who develops web-applications using the Java web-tier.

# Why use container-managed security? #

Container-managed security allows you to worry about your application instead of theres some bug in your code that allows unauthorized access. You will not need to check for the type of user in every single jsp-page and servlet, instead you just declare all pages under /admin/ to be accessible only for users with role admin for example.

# Doesnt the Java web-spec define different login-methods? #

Yes, but unfortunately these are highly inflexible. Basically there is only Browser-managed login (Basic and Digest), Form-based login and client-cert login. The first project we did that required more than this, specifically needed a way to handle a otp-login (one-time-password) and also a way to really log out a user.
Back then we looked at multiple possible solutions, but couldnt find anything that felt like a "clean" path. So we started working on this project, first as a Tomcat-valva, later based on JSR-196. The most current version actually has both, so it can be used in plain Tomcat, too!

# Why not just base an Authenticator directly on JSR-196? #

Thats actually one of our early steps. But we had 2 little problems with that.
First we discovered that the API is a little technical, which means there is no easy way to perform common tasks. For example it would always be tricky to get the sequence right when forwarding the user to a different page. So we provide easy to use methods for these common actions.
Second and more important, we were restarting Glassfish all day long, because the JSR-196 authenticator is not part of the web-app but has to be installed directly inside Glassfish. So on every minor code-change you would have to restart the whole app-server. With AuthenticRoast you can simply redeploy your web-app which resulted in huge speedups in our development.