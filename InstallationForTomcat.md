# Introduction #

AuthenticRoast needs a base module to be registered with the web-container. In the case of a standalone Tomcat this is a simple Tomcat-valve.

# Installation #

The simplest way to install this valve is using the Tomcats context.xml. If you dont have any in your web-project yet, create a file called context.xml inside the WEB-INF/ folder of your app.

Now add the following line inside the top-level element:

```
    <Valve className="name.aikesommer.authenticator.TomcatAuthenticator" />
```

If you have just created the file, the content should be:

```
<Context>
    <Valve className="name.aikesommer.authenticator.TomcatAuthenticator" />
</Context>
```

If this change is not picked up by Tomcat, make sure to remove the file at (TOMCAT-ROOT)/conf/Catalina/localhost/(NAME).xml. Replace (NAME) with the context-path of your webapp and (TOMCAT-ROOT) with the directory where you installed Tomcat.

Next copy AuthenticRoast-API and AuthenticRoast-Impl to (TOMCAT-ROOT)/lib/.

That's it, you can now proceed to RegisteringYourAuthenticator!