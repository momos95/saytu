package com.saytu.scan.adapter;

import com.saytu.core.scan.ScanContext;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Command line of a Java tool run in its own JVM (never inside the worker's JVM). */
final class JvmTool {

    private JvmTool() {
    }

    /**
     * @param java      java executable
     * @param classpath directory holding the tool's jars
     * @param mainClass entry point
     */
    static List<String> command(Path java, Path classpath, String mainClass, ScanContext context) {
        List<String> argv = new ArrayList<>();
        argv.add(java.toString());
        argv.add("-Xmx" + Math.max(128, context.limits().jvmHeapBytes() / (1024 * 1024)) + "m");
        argv.add("-XX:+UseSerialGC");
        argv.add("-XX:TieredStopAtLevel=1");
        argv.add("-Djava.io.tmpdir=" + context.workDir());
        argv.add("-Duser.home=" + context.workDir());
        argv.add("-Djava.awt.headless=true");
        argv.add("-cp");
        argv.add(classpath.resolve("*").toString());
        argv.add(mainClass);
        return argv;
    }
}
