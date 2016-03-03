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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.contrastsecurity.joogle.JoogleContext.MatchMode;
import com.contrastsecurity.joogle.checkers.CreatesTypeChecker;
import com.contrastsecurity.joogle.checkers.DeclaresFinalize;
import com.contrastsecurity.joogle.checkers.DeclaresHashCodeOrEquals;
import com.contrastsecurity.joogle.checkers.ImplementsTypeChecker;
import com.contrastsecurity.joogle.checkers.ZeroArgConstructorChecker;
import com.contrastsecurity.joogle.checkers.ZeroArgConstructorUsesStaticChecker;

/**
 * The main class for Joogle. 
 */
public class Joogle {
	
	private static final String OUTPUT_CSV_FILE = "csv";
	private static final String INPUT_FILE = "i";
	private static final String SUPPRESS_STDOUT = "s";
	private static final String INCLUDE_JRE = "j";
	private static final String VERBOSE = "v";
	
	private static final String MODE = "mode";
	private static final String ALLOW_INNER = "allowInner";
	private static final String ALLOW_INTERFACES = "allowInterfaces";
	
	private static final String DECLARES_EQUALS_OR_HASH_CODE = "declaresEqualsOrHashCode";
	private static final String DECLARES_FINALIZE = "declaresFinalize";
	private static final String CREATES_TYPE = "createsType";
	private static final String IMPLEMENTS_TYPE = "implementsType";
	private static final String STATIC_ACCESS_CONSTRUCTORS = "staticAccessConstructors";
	private static final String ZERO_ARG_CONSTRUCTOR = "zeroArgConstructor";
	
	public static void main(String[] args) throws Exception {
		
		/*
		 * Register command line options.
		 */
		Options options = new Options();
		options.addOption(MODE, true, "match mode -- values can be AND or OR; default is OR");
		options.addOption(VERBOSE, false, "include verbose output");
		options.addOption(INCLUDE_JRE, false, "don't include the JRE in the search");
		options.addOption(SUPPRESS_STDOUT, false, "suppress stdout output");
		options.addOption(INPUT_FILE, true, "input file containing paths to search, separated by newlines");
		options.addOption(OUTPUT_CSV_FILE, true, "a target file to dump csv output");
		options.addOption(ALLOW_INNER, false, "allow inner classes to be searched");
		options.addOption(ALLOW_INTERFACES, false, "allow interfaces to be searched");
		options.addOption(ZERO_ARG_CONSTRUCTOR, false, "find gadgets with zero-arg constructors");
		options.addOption(STATIC_ACCESS_CONSTRUCTORS, false, "find gadgets with zero-arg constructors interacting with static fields/methods");
		options.addOption(IMPLEMENTS_TYPE, true, "find gadgets that implement (via abstract classes or interfaces)");
		options.addOption(CREATES_TYPE, true, "find gadgets that create concrete classes of given type");
		options.addOption(DECLARES_FINALIZE, false, "find gadgets that declare finalize() methods");
		options.addOption(DECLARES_EQUALS_OR_HASH_CODE, false, "find gadgets that override equals() or hashCode()");
		
		try {
			CommandLineParser parser = new DefaultParser();
			CommandLine cmd = parser.parse( options, args);
			scan(options, cmd);
		} catch (ParseException e) {
			LOG.error("Invalid argument: {}", e.getMessage());
			printUsage(options);
		}
	}

	private static void scan(Options options, CommandLine cmd) throws IOException {
		/*
		 * Add the user JRE to search, unless the user requested not to.
		 */
		Set<Path> paths = new HashSet<Path>();
		
		String inputFile = cmd.getOptionValue(INPUT_FILE);
		if(!cmd.hasOption('j')) {
			paths.add(Paths.get(System.getProperty("java.home")));
		} else if(inputFile == null) {
			LOG.error("The JRE was suppressed (with -j) and no input file (-i) was specified. Nowhere to search.");
			LOG.error("Exiting.");
			return;
		}
		
		/*
		 * If the user has an input file, add its paths to our search.
		 */
		if(inputFile != null) {
			File file = new File(inputFile);
			if(file.exists() && file.canRead()) {
				List<String> targetPaths = FileUtils.readLines(file);
				for(String path : targetPaths) {
					path = path.trim();
					if(!path.startsWith("#")) {
						paths.add(Paths.get(path));
					}
				}
			} else {
				LOG.error("Input file {} could not be read", inputFile);
			}
		}
		
		LOG.info("**********");
		LOG.info("* joogle *");
		LOG.info("**********");
		LOG.info("Scanning {} paths", paths.size());
		
		/*
		 * Create the context from the command line options passed in.
		 */
		JoogleContext context = buildContext(cmd);
		if(context.checkers().isEmpty()) {
			LOG.error("No class checkers were registered -- nothing to filter on. Exiting.");
			printUsage(options);
			return;
		}
		
		/*
		 * Prevent our own classes from being recognized as gadgets.
		 */
		context.blacklist("com.contrastsecurity");
		context.blacklist("com.aspectsecurity");
		
		Joogle joogle = new Joogle();
		joogle.scanDir(paths, context);
		
		LOG.info("Scanned {} classes", context.classesScanned());
		LOG.info("Scanned {} jars", context.jarsScanned());
	}

	private static void printUsage(Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp( "joogle", options );
	}
	
	/**
	 * Build the configuration based on the command-line arguments.
	 */
	static JoogleContext buildContext(CommandLine cmd) {
		JoogleContext context = new JoogleContext();
		context.allowInnerClasses(cmd.hasOption(ALLOW_INNER));
		context.allowInterfaces(cmd.hasOption(ALLOW_INTERFACES));
		context.verbose(cmd.hasOption(VERBOSE));
		
		String mode = cmd.getOptionValue(MODE);
		if(mode == null || "or".equals(mode)) {
			context.matchMode(MatchMode.OR);	
		} else if("and".equals(mode)){
			context.matchMode(MatchMode.AND);
		} else {
			LOG.error("Unknown match mode {} -- should be [and|or] -- defaulting to OR", mode);
			context.matchMode(MatchMode.OR);
		}
		
		if(cmd.hasOption(ZERO_ARG_CONSTRUCTOR)) {
			ZeroArgConstructorChecker zeroArg = new ZeroArgConstructorChecker();
			context.addChecker(zeroArg);
		}
		
		if(cmd.hasOption(STATIC_ACCESS_CONSTRUCTORS)) {
			ZeroArgConstructorUsesStaticChecker usesStatic = new ZeroArgConstructorUsesStaticChecker();
			context.addChecker(usesStatic);
		}
		
		if(cmd.hasOption(DECLARES_FINALIZE)) {
			context.addChecker(new DeclaresFinalize());
		}
		
		if(cmd.hasOption(DECLARES_EQUALS_OR_HASH_CODE)) {
			context.addChecker(new DeclaresHashCodeOrEquals());
		}
		
		String createsType = cmd.getOptionValue(CREATES_TYPE, null);
		if(createsType != null) {
			context.addChecker(new CreatesTypeChecker(createsType.replace('/','.')));
		}
		
		String implementsType = cmd.getOptionValue(IMPLEMENTS_TYPE, null);
		if(implementsType != null) {
			context.addChecker(new ImplementsTypeChecker(implementsType.replace('/','.')));
		}
		
		String csv = cmd.getOptionValue(OUTPUT_CSV_FILE);
		if(csv != null) {
			context.csvOutputFile(csv);
		}
		
		return context;
	}

	/**
	 * Recursively scan a directory for .jar files and .class files.
	 */
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
	
	/**
	 * Determine if the class isn't blacklisted or disallowed by settings.
	 */
	boolean isAllowedClass(String name, JoogleContext context) {
		if(name.endsWith(".class")) {
			if(context.allowInnerClasses() ? true : !name.contains("$")) {
				String className = name.replace('/', '.');
				return !context.isBlacklisted(className);
			}
		}
		return false;
	}

	/**
	 * Scan the contents of the given jar, adding the results to the context as found.
	 */
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
	
	/**
	 * Use the registered ClassCheckers to match the class. 
	 */
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
				} else if(MatchMode.AND.equals(context.matchMode())) {
					return;
				}
			}
			
			context.onClassScanned();
			
			if(matches != null && !context.alreadyMatched(clazz)) {
				report(matches, clazz, context, path);
			}
			
		} catch (Exception e) {
			LOG.debug("Problem scanning class", e);
		}
	}
	
	/**
	 * Report the matched class to the log, and possibly the CSV file.
	 */
	void report(List<ClassMatch> matches, ClassNode clazz, JoogleContext context, String path) {
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
		
		String csvOutputFile = context.csvOutputFile();
		if(csvOutputFile != null && !csvOutputFile.isEmpty()) {
			addToCsvFile(csvOutputFile, path, url, className);
		}
		
	}

	/**
	 * Attempt to add the match to the CSV file.
	 */
	void addToCsvFile(String csvOutputFile, String path, String url, String className) {
		String row = className + "," + path + "," + url + System.getProperty("line.separator");
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(csvOutputFile, true);
			fos.write(row.getBytes());
		} catch(IOException e) {
			LOG.error("Problem writing CSV row", e);
		} finally {
			IOUtils.closeQuietly(fos);
		}
	}
	
	private static final Logger LOG = LoggerFactory.getLogger(Joogle.class);
}
