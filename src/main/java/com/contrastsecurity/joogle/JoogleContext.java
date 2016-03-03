package com.contrastsecurity.joogle;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.objectweb.asm.tree.ClassNode;

/**
 * Holds the configuration and execution context of a Joogle scan.
 */
public class JoogleContext {
	
	public enum MatchMode {
		OR,
		AND
	}
	
	private List<ClassChecker> checkers;
	private boolean allowInnerClasses;
	private boolean allowInterfaces;
	private boolean verbose;
	private boolean quiet;
	private MatchMode matchMode;
	private Map<String,Integer> matches;
	private String csvOutputFile;
	
	private int classesScanned;
	private int jarsScanned;
	private Set<String> blacklist;
	
	public JoogleContext() {
		this.verbose = false;
		this.quiet = false;
		this.checkers = new ArrayList<ClassChecker>();
		this.matchMode = MatchMode.OR;
		this.classesScanned = 0;
		this.jarsScanned = 0;
		this.matches = new HashMap<String,Integer>();
		this.blacklist = new HashSet<String>();
	}
	
	public void addChecker(ClassChecker checker) {
		checkers.add(checker);
	}

	public Collection<ClassChecker> checkers() {
		return checkers;
	}
	
	public boolean alreadyMatched(ClassNode classNode) {
		Integer value = matches.put(classNode.name, 1);
		return value != null;
	}

	public void allowInnerClasses(boolean b) {
		this.allowInnerClasses = false;
	}
	
	public boolean allowInnerClasses() {
		return allowInnerClasses;
	}

	public void allowInterfaces(boolean b) {
		this.allowInterfaces = b;
	}
	
	public boolean allowInterfaces() {
		return allowInterfaces;
	}
	
	public MatchMode matchMode() {
		return matchMode;
	}
	
	public void matchMode(MatchMode matchMode) {
		this.matchMode = matchMode;
	}
	
	public void onClassScanned() {
		this.classesScanned++;
	}
	
	public int classesScanned() {
		return this.classesScanned;
	}
	
	public int jarsScanned() {
		return this.jarsScanned;
	}
	
	public void onJarScanned() {
		this.jarsScanned++;
	}
	
	public boolean verbose() {
		return verbose;
	}
	
	public void verbose(boolean verbose) {
		this.verbose = verbose;
	}
	
	public String csvOutputFile() {
		return csvOutputFile;
	}

	public void csvOutputFile(String csvOutputFile) {
		this.csvOutputFile = csvOutputFile;
	}
	
	public void blacklist(String pkg) {
		this.blacklist.add(pkg);
	}
	
	public boolean isBlacklisted(String className) {
		for(String entry : blacklist) {
			if(className.startsWith(entry)) {
				return true;
			}
		}
		return false;
	}

	public void quiet(boolean quiet) {
		this.quiet = quiet;
	}
	
	public boolean quiet() {
		return quiet;
	}
}
