package com.contrastsecurity.joogle.checkers;

import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;
import com.contrastsecurity.joogle.TypeUtil;

/**
 * Checks if the class being scanned implements/extends another type.
 */
public class ImplementsTypeChecker extends ClassChecker {
	
	private String type;
	
	public ImplementsTypeChecker(String type) {
		this.type = type;
	}

	@Override
	public ClassMatch check(ClassNode classNode) {
		List<String> ifaces = classNode.interfaces;
		ClassMatch match = new ClassMatch();
		for(String iface : ifaces) {
			if(iface.equals(type)) {
				match.evidence("implements " + TypeUtil.toDisplayType(type));
				match.matched(true);
			}
		}
		if(!match.matched()) {
			match.matched(type.equals(classNode.superName));
		}
		return match;
	}

}
