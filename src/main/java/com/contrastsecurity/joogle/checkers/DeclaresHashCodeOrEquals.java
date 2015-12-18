package com.contrastsecurity.joogle.checkers;

import java.util.List;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;

public class DeclaresHashCodeOrEquals extends ClassChecker {

	@Override
	public ClassMatch check(ClassNode classNode) {
		List<MethodNode> methods = classNode.methods;
		ClassMatch match = new ClassMatch();
		for(MethodNode method : methods) {
			if("equals".equals(method.name) && "(Ljava/lang/Object;)Z".equals(method.desc)) {
				match.matched(true);
				match.evidence("implements equals()");
			}
			if("hashCode".equals(method.name) && "()I".equals(method.desc)) {
				match.matched(true);
				match.evidence("implements hashCode()");
			}
		}
		return match;
	}

}
