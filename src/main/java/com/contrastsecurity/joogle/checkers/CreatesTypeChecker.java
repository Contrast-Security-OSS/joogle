package com.contrastsecurity.joogle.checkers;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.contrastsecurity.joogle.ClassChecker;
import com.contrastsecurity.joogle.ClassMatch;

public class CreatesTypeChecker extends ClassChecker implements Opcodes {

	private String type;

	public CreatesTypeChecker(String type) {
		this.type = type;
	}

	@Override
	public ClassMatch check(ClassNode classNode) {
		ClassMatch match = new ClassMatch();
		for(MethodNode method : classNode.methods) {
			InsnList insns = method.instructions;
			for(int i=0;i<insns.size();i++) {
				AbstractInsnNode insn = insns.get(i);
				int opcode = insn.getOpcode();
				if(opcode == INVOKESPECIAL) {
					MethodInsnNode call = (MethodInsnNode)insn;
					if(type.equals(call.owner)) {
						match.matched(true);
						match.evidence("creates new " + call.owner.replace('/', '.'));
					}
				}
			}	
		}
		return match;
	}

}
