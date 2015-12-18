package com.contrastsecurity.joogle.checkers;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;

public class ZeroArgConstructorChecker extends ClassChecker {
	
	@Override
	public ClassMatch check(ClassNode classNode) {
		ClassMatch match = new ClassMatch();
		for(MethodNode method : classNode.methods) {
			if("<init>".equals(method.name) && "()V".equals(method.desc)) {
				match.matched(true);
				match.evidence("has zero-argument constructor");
			}
		}
		return match;
	}

	
}
