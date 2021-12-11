# Log4jPatch

Kudos to Volker Simonis for the original patch, he continues to amaze and 
delight in the Java industry :-) - Original patch at https://github.com/simonis/Log4jPatch

This is a POC of a simple tool which injects a Java agent into a running JVM process. 
The agent will patch the `lookup()` method of all loaded `org.apache.logging.log4j.core.lookup.JndiLookup` 
instances to unconditionally return the string "Patched JndiLookup::lookup()". 
This should fix the [CVE-2021-44228](https://www.randori.com/blog/cve-2021-44228/) 
remote code execution vulnerability in Log4j without restarting the Java process.

This has been currently only tested with JDK 8 & 11!

**WARNING: HERE BE DRAGONS and DANGER WILL ROBINSON!**
This patch should only ever be run if:

1. You are unable to upgrade your log4j to 2.15.0 and/or restart your JVM
2. You are unable to change the system property as per https://logging.apache.org/log4j/2.x/security.html and/or restart your JVM.
3. You are willing to risk freezing your live running JVM (which would mean you would have to restart it anyhow).

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

## Known issues

If you get an error like:
```
Exception in thread "main" com.sun.tools.attach.AttachNotSupportedException: The VM does not support the attach mechanism
	at jdk.attach/sun.tools.attach.HotSpotAttachProvider.testAttachable(HotSpotAttachProvider.java:153)
	at jdk.attach/sun.tools.attach.AttachProviderImpl.attachVirtualMachine(AttachProviderImpl.java:56)
	at jdk.attach/com.sun.tools.attach.VirtualMachine.attach(VirtualMachine.java:207)
	at Log4jPatch.loadInstrumentationAgent(Log4jPatch.java:115)
	at Log4jPatch.main(Log4jPatch.java:139)
```
this means that your JVM is refusing any kind of help because it is running with `-XX:+DisableAttachMechanism` or 
it's just not a happy camper, refer to the top of this file for the full mitigation.
