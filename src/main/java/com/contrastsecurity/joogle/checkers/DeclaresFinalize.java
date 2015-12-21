package com.contrastsecurity.joogle.checkers;

import java.util.List;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;

public class DeclaresFinalize extends ClassChecker {

	@Override
	public ClassMatch check(ClassNode classNode) {
		List<MethodNode> methods = classNode.methods;
		ClassMatch match = new ClassMatch();
		for(MethodNode method : methods) {
			if("finalize".equals(method.name) && "()V".equals(method.desc)) {
				match.matched(true);
				match.evidence("implements finalize()");
			}
		}
		return match;
	}

}
