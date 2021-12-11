import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.MethodVisitor;
import jdk.internal.org.objectweb.asm.Opcodes;

/**
 * See https://github.com/advisories/GHSA-jfh8-c2jp-5v3q/dependabot
 * <p>
 * Kudos to Volker Simonis for the original patch, he continues to amaze and
 * delight in the Java industry :-) - https://github.com/simonis/Log4jPatch
 * <p>
 * WARNING: HERE BE DRAGONS and DANGER WILL ROBINSON!
 * <p>
 * This patch should only ever be run if:
 * <p>
 * 1. You are unable to upgrade your log4j to 2.15.0 and/or restart your JVM
 * 2. You are unable to change the system property as per
 * https://logging.apache.org/log4j/2.x/security.html and/or restart your JVM
 * 3. You are willing to risk freezing your live running JVM (which would mean
 * you would have to restart it anyhow.
 * <p>
 * This is a class is an all-in-one utility that:
 * <p>
 * 1. Turns itself into a Java Agent
 * 2. Attaches to all viable JVMs (running as the same user)
 * 3. Uses a ClassWalker visitor to find the vulnerable
 * org/apache/logging/log4j/core/lookup/JndiLookup method and patches it
 * using ASM to override the return to return nothing.
 * <p>
 * See the README.md file for javac configuration (--add-exports is required)
 */
public class Log4jPatch {

    private static final String ORG_APACHE_LOGGING_LOG_4_J_CORE_LOOKUP_JNDI_LOOKUP = "org.apache.logging.log4j.core.lookup.JndiLookup";
    private static final String LOG4J_JNDI_CLASS_TO_PATCH = "org/apache/logging/log4j/core/lookup/JndiLookup";

    /**
     * The main method for the JavaAgent that we use for performing the transform
     *
     * @param args            - Required parameter (but is empty in this case)
     * @param instrumentation The instrumentation class we'll use to transform.
     */
    public static void agentmain(String args, Instrumentation instrumentation) {

        System.out.println("Loading the Log4JPatch Java Agent.");

        ClassFileTransformer transformer = new ClassFileTransformer() {

            /**
             * When the agent runs this transform function will be fired. It
             * visits all the classes in the target JVM looking for the
             * LOG4J_JNDI_CLASS_TO_PATCH class to transform the lookup() method.
             *
             * @param loader - Classloader used to start searching
             * @param className - The class we are looking for
             * @param classBeingRedefined - Not used
             * @param protectionDomain - Not used
             * @param classfileBuffer - Not used
             * @return The transformed class/method
             */
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {

                if (LOG4J_JNDI_CLASS_TO_PATCH.equals(className)) {
                    System.out.println("Transforming " + className + " (" + loader + ")");
                    ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                    MethodInstrumentorClassVisitor classVisitor = new MethodInstrumentorClassVisitor(classWriter);
                    ClassReader classReader = new ClassReader(classfileBuffer);
                    classReader.accept(classVisitor, 0);
                    return classWriter.toByteArray();
                } else {
                    return null;
                }
            }
        };

        instrumentation.addTransformer(transformer, true);

        for (Class aClass : instrumentation.getAllLoadedClasses()) {
            if (ORG_APACHE_LOGGING_LOG_4_J_CORE_LOOKUP_JNDI_LOOKUP.equals(aClass.getName())) {
                System.out.println("Patching " + aClass + " (" + aClass.getClassLoader() + ")");
                try {
                    instrumentation.retransformClasses(aClass);
                } catch (UnmodifiableClassException uce) {
                    System.err.println("Unable to transform the vulnerable class" + uce);
                }
            }
        }

        instrumentation.removeTransformer(transformer);

        // Re-add the transformer with 'canRetransform' set to false
        // for class instances which might get loaded in the future.
        instrumentation.addTransformer(transformer, false);
    }

    /**
     * The visitor that finds the lookup() method that we want to transform
     */
    static class MethodInstrumentorClassVisitor extends ClassVisitor {

        // We use ASM5 to support Java 8 and above
        public MethodInstrumentorClassVisitor(ClassVisitor classVisitor) {
            super(Opcodes.ASM5, classVisitor);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor methodVisitor = cv.visitMethod(access, name, desc, signature, exceptions);
            if ("lookup".equals(name)) {
                methodVisitor = new MethodInstrumentorMethodVisitor(methodVisitor);
            }
            return methodVisitor;
        }
    }

    /**
     * The Visitor class that applies the patch via ASM
     * It forces an empty return in the vulnerable lookup() method
     */
    static class MethodInstrumentorMethodVisitor extends MethodVisitor implements Opcodes {

        public MethodInstrumentorMethodVisitor(MethodVisitor methodVisitor) {
            super(Opcodes.ASM5, methodVisitor);
        }

        /**
         * The patch. It finds the lookup() function and makes it return nothing
         */
        @Override
        public void visitCode() {
            mv.visitCode();
            mv.visitLdcInsn("Patched JndiLookup::lookup()");
            mv.visitInsn(ARETURN);
        }
    }

    // Name of this class, used for filtering myself out of the patching process
    private static String myName = Log4jPatch.class.getName();

    /**
     * Patch all the JVMs that we find.
     *
     * @param pids - List of pids for the target JVMs
     * @throws Exception
     */
    private static void patchAllJVMs(String[] pids) throws Exception {

        File jarFile = null;
        try {
            jarFile = createAgentJar();

            for (String pid : pids) {
                patchJVM(jarFile, pid);
            }
        } finally {
            if (jarFile != null) {
                boolean deleted = jarFile.delete();
                if (!deleted) {
                    System.err.println("Failed to delete " + jarFile.getAbsolutePath());
                }
            }
        }
    }

    /**
     * Patch a JVM by connecting to it via ourselves as a Java Agent.
     * When the agent attaches the payload is delivered (see agentmain method)
     *
     * @param jarFile The Java Agent (ourselves)
     * @param pid The pid of the JVM
     */
    private static void patchJVM(File jarFile, String pid) {
        if (pid != null) {
            try {
                VirtualMachine vm = VirtualMachine.attach(pid);
                // The loadAgent call is what runs the patch that we created in the
                // earlier createAgentJar phase.
                vm.loadAgent(jarFile.getAbsolutePath());
            } catch (Exception e) {
                System.err.println(e);
                System.err.println("\nCouldn't load the agent into JVM process " + pid);
                return;
            }
            System.out.println("\nSuccessfully loaded the agent into JVM process " + pid);
            System.out.println("  Look at stdout of JVM process " + pid + " for more information");
        }
    }

    /**
     * This method creates the JAR file which is an Agent and effectively puts
     * itself inside the agent.
     *
     * @return The JAR file (which is a Java Agent) with this class's bytecode
     * embedded in it, ready to be executed
     * @throws Exception
     */
    private static File createAgentJar() throws Exception {
        String[] innerClasses = new String[]{"", /* this is for Log4jPatch itself */
                "$1",
                "$MethodInstrumentorClassVisitor",
                "$MethodInstrumentorMethodVisitor"};
        Manifest manifest = createManifest();
        File jarFile = File.createTempFile("agent", ".jar");
        jarFile.deleteOnExit();
        try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(jarFile), manifest)) {
            for (String klass : innerClasses) {
                String className = myName.replace('.', '/') + klass;
                byte[] buf = getBytecodes(className);
                jar.putNextEntry(new JarEntry(className + ".class"));
                jar.write(buf);
            }
        }
        return jarFile;
    }

    /**
     * Create the manifest entry for the JAR file (which is a Java Agent).
     * JAR files need a manifest ot be executed accurately.
     *
     * @return The manifest.
     */
    private static Manifest createManifest() {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(new Attributes.Name("Agent-Class"), myName);
        manifest.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");
        manifest.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
        return manifest;
    }

    /**
     * Get the bytecodes from ourselves (we're going to stream the byte code
     * of this class into the JAR). Yes this is a neat hack :-)
     *
     * @param myName - The name of the class to get the byte codes from (me!)
     * @return The bytearray containing the bytecodes of this class.
     * @throws Exception
     */
    private static byte[] getBytecodes(String myName) throws Exception {
        try (InputStream is = Log4jPatch.class.getResourceAsStream(myName + ".class");
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buf = new byte[4096];
            int len;
            if (is != null) {
                while ((len = is.read(buf)) != -1) {
                    baos.write(buf, 0, len);
                }
                return baos.toByteArray();
            } else {
                throw new Exception("InputStream was null");
            }
        }
    }

    /**
     * Entrypoint into this Log4JPatch utility.
     *
     * @param args - Log4jPatch [<pid> [<pid> ..]]"
     * @throws Exception - Note this program can crash fairly easily so make
     *                     sure you are able to capture stderr
     */
    public static void main(String args[]) throws Exception {

        System.out.println("Starting Log4JPatch Utility.");

        String jvmPidsToPatch[];

        if (args.length == 0) {

            // Typecasting a null seems odd but getMonitoredHost needs you to do this.
            MonitoredHost host = MonitoredHost.getMonitoredHost((String) null);
            Set<Integer> activeVmPids = host.activeVms();
            jvmPidsToPatch = new String[activeVmPids.size()];

            int count = 0;
            // Convert numeric pids to String because the attach API later on
            // needs a String type for the pid
            for (Integer pid : activeVmPids) {
                MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(pid.toString()));
                String mainClass = MonitoredVmUtil.mainClass(jvm, true);

                // Filter out myself.
                // TODO Might be better to do this via my own pid
                if (!myName.equals(mainClass)) {
                    System.out.println(pid + ": " + mainClass);
                    jvmPidsToPatch[count++] = pid.toString();
                }
            }

            // If there are any JVMs left that we can attach to to then ask the
            // user if they want to patch all of them.
            // TODO This is a batch operation, we could offer a 1 by 1 option.
            if (count > 0) {
                System.out.print("\nPatch all JVMs? (y/N) : ");
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                String answer = in.readLine();

                if (!"y".equalsIgnoreCase(answer)) {
                    return;
                }
            }
            // TODO Extracxt this to its on method for SRP
        } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
            System.out.println("usage: Log4jPatch [<pid> [<pid> ..]]");
            return;
        } else {
            // TODO sanitise the args
            jvmPidsToPatch = args;
        }

        // Do the live patching
        patchAllJVMs(jvmPidsToPatch);
    }
}
