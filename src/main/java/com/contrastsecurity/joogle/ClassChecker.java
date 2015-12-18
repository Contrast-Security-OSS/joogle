package com.contrastsecurity.joogle;

import org.objectweb.asm.tree.ClassNode;

/**
 * A restricting class checker.
 */
public abstract class ClassChecker {
	
	public String getDescriptor() {
		return getClass().getSimpleName();
	}
	
	public abstract ClassMatch check(ClassNode classNode);
	
}
