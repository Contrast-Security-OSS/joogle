package com.contrastsecurity.joogle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.contrastsecurity.joogle.JoogleContext.MatchMode;
import com.contrastsecurity.joogle.checkers.CreatesTypeChecker;
import com.contrastsecurity.joogle.checkers.DeclaresFinalize;
import com.contrastsecurity.joogle.checkers.ImplementsTypeChecker;
import com.contrastsecurity.joogle.checkers.ZeroArgConstructorChecker;
import com.contrastsecurity.joogle.checkers.ZeroArgConstructorUsesStaticChecker;

public class Joogle {

	public static void main(String[] args) throws Exception {
		
		Joogle joogle = new Joogle();

		// add the user JRE to search
		Set<Path> paths = new HashSet<Path>();
		paths.add(Paths.get(System.getProperty("java.home")));
		
		// add user targets to search
		File file = new File("targets.txt");
		if(file.exists() && file.canRead()) {
			List<String> targetPaths = FileUtils.readLines(file);
			for(String path : targetPaths) {
				path = path.trim();
				if(!path.startsWith("#")) {
					paths.add(Paths.get(path));
				}
			}
		} else {
			LOG.warn("No targets.txt file seen -- only the JRE will be scanned");
		}
		
		LOG.info("**********");
		LOG.info("* joogle *");
		LOG.info("**********");
		LOG.info("Scanning {} paths", paths.size());
		
		JoogleContext context = createGadgetSearch();
		context.blacklist("com.contrastsecurity");
		context.blacklist("com.aspectsecurity");
		joogle.scanDir(paths, context);
		
		LOG.info("Scanned {} classes", context.classesScanned());
		LOG.info("Scanned {} jars", context.jarsScanned());
	}
	
	static JoogleContext createGadgetSearch() {
		JoogleContext context = new JoogleContext();
		context.allowInnerClasses(false);
		context.allowInterfaces(false);
		context.matchMode(MatchMode.AND);
		context.verbose(false);
		ZeroArgConstructorChecker zeroArg = new ZeroArgConstructorChecker();
		//ZeroArgConstructorUsesStaticChecker usesStatic = new ZeroArgConstructorUsesStaticChecker();
		//CreatesTypeChecker createsTypeChecker = new CreatesTypeChecker("java/lang/InvocationHandler");
		//context.addChecker(createsTypeChecker);
		//context.addChecker(usesStatic);
		context.addChecker(zeroArg);
		context.addChecker(new DeclaresFinalize());
		return context;
	}
	
	static JoogleContext createProxyHandlerSearch() {
		JoogleContext context = new JoogleContext();
		context.allowInnerClasses(false);
		context.allowInterfaces(false);
		context.verbose(false);
		context.matchMode(MatchMode.AND);
		context.addChecker(new ZeroArgConstructorChecker());
		context.addChecker(new ImplementsTypeChecker("java/lang/reflect/InvocationHandler"));
		return context;
	}

	public void scanDir(Set<Path> paths, final JoogleContext context) throws IOException {
		assert context.checkers() != null;
		for (Path dir : paths) {
			Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					String name = file.toFile().getName();
					String path = file.toFile().getPath();
					if (name.endsWith(".jar")) {
						LOG.debug("Scanning jar {}", path);
						scanJar(file.toFile(), context, path);
					} else if(isAllowedClass(name,context)) {
						scanClass(new FileInputStream(file.toFile()), context, path);
					}
					return FileVisitResult.CONTINUE;
				}

				
			});
		}
	}
	
	boolean isAllowedClass(String name, JoogleContext context) {
		if(name.endsWith(".class")) {
			if(context.allowInnerClasses() ? true : !name.contains("$")) {
				String className = name.replace('/', '.');
				return !context.isBlacklisted(className);
			}
		}
		return false;
	}

	void scanJar(File f, JoogleContext context, String path) throws IOException {
		JarFile jf = null;
		try {
			jf = new JarFile(f);
			Enumeration<JarEntry> e = jf.entries();
			while (e.hasMoreElements()) {
				JarEntry entry = e.nextElement();
				if (isAllowedClass(entry.getName(), context)) {
					LOG.debug("Scanning class {}", entry.getName());
					InputStream is = jf.getInputStream(entry);
					scanClass(is, context, path);
				}
			}
			context.onJarScanned();
		} catch (Exception e) {
			LOG.debug("Error scanning file {}", f.getPath());
		} finally {
			IOUtils.closeQuietly(jf);
		}
	}
	
	void scanClass(InputStream in, JoogleContext context, String path) {
		try {
			ClassReader cr = new ClassReader(in);
			ClassNode clazz = new ClassNode();
			cr.accept(clazz, 0);
			
			List<ClassMatch> matches = null;
			for(ClassChecker checker : context.checkers()) {
				ClassMatch match = checker.check(clazz);
				if(match.matched()) {
					if(matches == null) { 
						matches = new LinkedList<ClassMatch>(); 
					}
					matches.add(match);
				} else if(context.matchMode().equals(MatchMode.AND)) {
					return;
				}
			}
			
			context.onClassScanned();
			
			if(matches != null && !context.alreadyMatched(clazz)) {
				reportToConsole(matches, clazz, context, path);
			}
		} catch (Exception e) {
			LOG.debug("Problem scanning class", e);
		} finally {
			
		}
	}
	// ===========
	
	void reportToConsole(List<ClassMatch> matches, ClassNode clazz, JoogleContext context, String path) {
		String url = "http://grepcode.com/search?query=" + clazz.name.replace('/','.');
		String className = TypeUtil.toDisplayType(clazz.name);
		LOG.info("[!] Matched: {} - {} - {}", className, path, url);
		for(ClassMatch match : matches) {
			List<String> evidence = match.evidence();
			if(context.verbose()) {
				for(String str : evidence) {
					LOG.info("\t {}", str);	
				}
			}
		}
		String row = className + "," + path + "," + url + System.getProperty("line.separator");
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream("target/matches.csv", true);
			fos.write(row.getBytes());
		} catch(IOException e) {
			LOG.error("Problem writing CSV row", e);
		} finally {
			IOUtils.closeQuietly(fos);
		}
	}
	
	private static final Logger LOG = LoggerFactory.getLogger(Joogle.class);
}
