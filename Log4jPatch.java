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

public class Log4jPatch {

  private static int asmVersion() {
    try {
      Opcodes.class.getDeclaredField("ASM8");
      return 8 << 16 | 0 << 8; // Opcodes.ASM8
    } catch (NoSuchFieldException nsfe) {}
    try {
      Opcodes.class.getDeclaredField("ASM7");
      return 7 << 16 | 0 << 8; // Opcodes.ASM7
    } catch (NoSuchFieldException nsfe) {}
    try {
      Opcodes.class.getDeclaredField("ASM6");
      return 6 << 16 | 0 << 8; // Opcodes.ASM6
    } catch (NoSuchFieldException nsfe) {}
    try {
      Opcodes.class.getDeclaredField("ASM5");
      return 5 << 16 | 0 << 8; // Opcodes.ASM5
    } catch (NoSuchFieldException nsfe) {}
    System.out.println("Warning: ASM5 doesn't seem to be supported");
    return Opcodes.ASM4;
  }

  public static void agentmain(String args, Instrumentation inst) {

    int asm = asmVersion();
    System.out.println("Loading Java Agent (using ASM" + (asm >> 16) + ").");

    ClassFileTransformer transformer = new ClassFileTransformer() {
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
          if ("org/apache/logging/log4j/core/lookup/JndiLookup".equals(className)) {
            System.out.println("Transforming " + className + " (" + loader + ")");
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            MethodInstrumentorClassVisitor cv = new MethodInstrumentorClassVisitor(asm, cw);
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
    private int asm;

    public MethodInstrumentorClassVisitor(int asm, ClassVisitor cv) {
      super(asm, cv);
      this.asm = asm;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
      MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
      if ("lookup".equals(name)) {
        mv = new MethodInstrumentorMethodVisitor(asm, mv);
      }
      return mv;
    }
  }

  static class MethodInstrumentorMethodVisitor extends MethodVisitor implements Opcodes {

    public MethodInstrumentorMethodVisitor(int asm, MethodVisitor mv) {
      super(asm, mv);
    }

    @Override
    public void visitCode() {
      mv.visitCode();
      mv.visitLdcInsn("Patched JndiLookup::lookup()");
      mv.visitInsn(ARETURN);
    }
  }

  private static String myName = Log4jPatch.class.getName();

  private static void loadInstrumentationAgent(String[] pids) throws Exception {
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
    for (String pid : pids) {
      if (pid != null) {
        try {
          VirtualMachine vm = VirtualMachine.attach(pid);
          vm.loadAgent(jarFile.getAbsolutePath());
        } catch (Exception e) {
          System.out.println(e);
          System.out.println("\nError: couldn't loaded the agent into JVM process " + pid);
          continue;
        }
        System.out.println("\nSuccessfully loaded the agent into JVM process " + pid);
        System.out.println("  Look at stdout of JVM process " + pid + " for more information");
      }
    }
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

    String pid[];
    if (args.length == 0) {
      MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
      Set<Integer> pids = host.activeVms();
      pid = new String[pids.size()];
      int count = 0;
      for (Integer p : pids) {
        MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
        String mainClass = MonitoredVmUtil.mainClass(jvm, true);
        if (!myName.equals(mainClass)) {
          System.out.println(p + ": " + mainClass);
          pid[count++] = p.toString();
        }
      }
      if (count > 0) {
        System.out.print("\nPatch all JVMs? (y/N) : ");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String answer = in.readLine();
        if (!"y".equals(answer)) {
          return;
        }
      }
    } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
      System.out.println("usage: Log4jPatch [<pid> [<pid> ..]]");
      return;
    } else {
      pid = args;
    }
    loadInstrumentationAgent(pid);
  }
}
