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
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import com.sun.tools.attach.VirtualMachine;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.MethodVisitor;
import jdk.internal.org.objectweb.asm.Opcodes;

public class Log4jPatch {

  public static void agentmain(String args, Instrumentation inst) {
    System.out.println("Loading Java Agent.");

    ClassFileTransformer transformer = new ClassFileTransformer() {
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
          if ("org/apache/logging/log4j/core/lookup/JndiLookup".equals(className)) {
            System.out.println("Transforming " + className + " (" + loader + ")");
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            MethodInstrumentorClassVisitor cv = new MethodInstrumentorClassVisitor(cw);
            ClassReader cr = new ClassReader(classfileBuffer);
            cr.accept(cv, 0);
            return cw.toByteArray();
          } else {
            return null;
          }
        }
      };
    inst.addTransformer(transformer, true);

    for (Class c : inst.getAllLoadedClasses()) {
      if ("org.apache.logging.log4j.core.lookup.JndiLookup".equals(c.getName())) {
        System.out.println("Patching " + c + " (" + c.getClassLoader() + ")");
        try {
          inst.retransformClasses(c);
        } catch (UnmodifiableClassException uce) {
          System.out.println(uce);
        }
      }
    }

    inst.removeTransformer(transformer);
    // Re-add the transformer with 'canRetransform' set to false
    // for class instances which might get loaded in the future.
    inst.addTransformer(transformer, false);
  }

  static class MethodInstrumentorClassVisitor extends ClassVisitor {

    public MethodInstrumentorClassVisitor(ClassVisitor cv) {
      super(Opcodes.ASM5, cv);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
      MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
      if ("lookup".equals(name)) {
        mv = new MethodInstrumentorMethodVisitor(mv);
      }
      return mv;
    }
  }

  static class MethodInstrumentorMethodVisitor extends MethodVisitor implements Opcodes {

    public MethodInstrumentorMethodVisitor(MethodVisitor mv) {
      super(Opcodes.ASM5, mv);
    }

    @Override
    public void visitCode() {
      mv.visitCode();
      mv.visitLdcInsn("Patched JndiLookup::lookup()");
      mv.visitInsn(ARETURN);
    }
  }

  private static String myName = Log4jPatch.class.getName();

  private static void loadInstrumentationAgent(String pid) throws Exception {
    String[] innerClasses = new String[] {"", /* this is for Log4jPatch itself */
                                          "$1",
                                          "$MethodInstrumentorClassVisitor",
                                          "$MethodInstrumentorMethodVisitor"};
    // Create agent jar file on the fly
    Manifest m = new Manifest();
    m.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    m.getMainAttributes().put(new Attributes.Name("Agent-Class"), myName);
    m.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");
    m.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
    File jarFile = File.createTempFile("agent", ".jar");
    jarFile.deleteOnExit();
    JarOutputStream jar = new JarOutputStream(new FileOutputStream(jarFile), m);
    for (String klass : innerClasses) {
      String className = myName.replace('.', '/') + klass;
      byte[] buf = getBytecodes(className);
      jar.putNextEntry(new JarEntry(className + ".class"));
      jar.write(buf);
    }
    jar.close();
    VirtualMachine vm = VirtualMachine.attach(pid);
    vm.loadAgent(jarFile.getAbsolutePath());
    System.out.println("Successfully loaded the agent into JVM process " + pid);
    System.out.println("Look at stdout of JVM process " + pid + " for more information");
  }

  private static byte[] getBytecodes(String myName) throws Exception {
    InputStream is = Log4jPatch.class.getResourceAsStream(myName + ".class");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buf = new byte[4096];
    int len;
    while ((len = is.read(buf)) != -1) baos.write(buf, 0, len);
    buf = baos.toByteArray();
    return buf;
  }

  public static void main(String args[]) throws Exception {
    String pid;
    if (args.length == 1) {
      pid = args[0];
    } else {
      System.out.println("usage: Log4jPatch <pid>");
      return;
    }
    loadInstrumentationAgent(pid);
  }
}
