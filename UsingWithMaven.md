# Introduction #

We use Maven to build AuthenticRoast. So if your also using Maven you can significantly ease the process by specifying our repository.


# Repository #

Simply add this repository to your pom.xml:

```
        <repository>
            <id>authenticroast-releases</id>
            <name>AuthenticRoast Repository - Releases</name>
            <url>http://authenticroast.googlecode.com/svn/maven2/releases/</url>
            <releases>
                <enabled>true</enabled>
            </releases>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
```


# Artifacts #

The artifacts are:

```
        <dependency>
            <groupId>name.aikesommer</groupId>
            <artifactId>AuthenticRoast-API</artifactId>
            <version>0.3.3</version>
        </dependency>
        <dependency>
            <groupId>name.aikesommer</groupId>
            <artifactId>AuthenticRoast-Impl</artifactId>
            <version>0.3.3</version>
        </dependency>
        <dependency>
            <groupId>name.aikesommer</groupId>
            <artifactId>AuthenticRoast-Extras</artifactId>
            <version>0.3.3</version>
        </dependency>
        <dependency>
            <groupId>name.aikesommer</groupId>
            <artifactId>AuthenticRoast-Samples</artifactId>
            <version>0.3.3</version>
        </dependency>
```