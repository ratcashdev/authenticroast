# Introduction #

You will need to specify, which authenticator class you wish to use. There are a few to start off with in the Extras and Samples modules.


# Using init-parameters #

You can specify the class to use using an init-parameter. Simply add a param like this inside the top-level element in your web.xml:

```
    <context-param>
        <param-name>roast.authenticator.class</param-name>
        <param-value>my.very.own.Authenticator</param-value>
    </context-param>
```

This is only tested with a standalone Tomcat for now.


# Using an application listener #

You can programmatically register your authenticator using:

```
name.aikesommer.authenticator.Registry.forContext(servletContext).register(myAuthenticator);
```

This is best done inside an application-listener.