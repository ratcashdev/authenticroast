<%-- 
    Document   : login
    Created on : 13.02.2010, 18:18:35
    Author     : ajs
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Login</title>
    </head>
    <body>
        <h1>Login</h1>

        <p>
            Use "test" as username and password!
        </p>

        <form action="j_security_check" method="POST">
            Username: <input type="text" name="j_username"><br>
            Password: <input type="password" name="j_password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
</html>
