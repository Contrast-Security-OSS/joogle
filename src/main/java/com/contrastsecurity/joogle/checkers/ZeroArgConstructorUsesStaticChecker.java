package com.contrastsecurity.joogle.checkers;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;
import com.contrastsecurity.joogle.TypeUtil;

/**
 * Check if a no-arg constructor uses static fields or methods.
 */
public class ZeroArgConstructorUsesStaticChecker extends ClassChecker implements Opcodes {

	@Override
	public ClassMatch check(ClassNode clazz) {
		ClassMatch match = new ClassMatch();
		for(MethodNode method : clazz.methods) {
			if("<init>()V".equals(method.name + method.desc)) {
				continue;
			}
			InsnList insns = method.instructions;
			for(int i=0;i<insns.size();i++) {
				AbstractInsnNode insn = insns.get(i);
				int opcode = insn.getOpcode();
				if(opcode == INVOKESTATIC) {
					MethodInsnNode call = (MethodInsnNode)insn;
					match.matched(true);
					match.evidence("calls static " + TypeUtil.toDisplayType(call.owner) + "." + call.name + call.desc);
				}
				if(opcode == GETSTATIC) {
					FieldInsnNode fieldCall = (FieldInsnNode)insn;
					match.matched(true);
					match.evidence("uses static field " + TypeUtil.toDisplayType(fieldCall.owner) + "." + fieldCall.name +" (" + fieldCall.desc + ")");
				}
			}	
		}
		
		return match;
	}

}
