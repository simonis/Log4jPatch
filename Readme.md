# Log4jPatch

This is a POC of a simple tool which injects a Java agent into a running JVM process. The agent will patch the `lookup()` method of all loaded `org.apache.logging.log4j.core.lookup.JndiLookup` instances to unconditionally return the string "Patched JndiLookup::lookup()". This should fix the [CVE-2021-44228](https://www.randori.com/blog/cve-2021-44228/) remote code execution vulnerability in Log4j without restarting the Java process.

This has been currently only tested with JDK 8 & 11!

**Disclaimer**: this code is provided in the hope that it will be useful, but without any warranty!

## Building

JDK 8
```
javac -XDignore.symbol.file=true -cp <java-home>/lib/tools.jar Log4jPatch.java
```

JDK 11
```
javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED Log4jPatch.java
```

## Running

JDK 8
```
java -cp .:<java-home>/lib/tools.jar Log4jPatch <java-pid>
```

JDK 11
```
java Log4jPatch <java-pid>
```
