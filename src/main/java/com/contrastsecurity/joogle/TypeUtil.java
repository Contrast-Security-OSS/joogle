package com.contrastsecurity.joogle;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.ParameterNode;

public class TypeUtil {

    private static Map<String,String> DISPLAY_CACHE;
    static {
    	DISPLAY_CACHE = new HashMap<String,String>();
    	DISPLAY_CACHE.put("I", "int");
    	DISPLAY_CACHE.put("[I", "int[]");
    	DISPLAY_CACHE.put("J", "long");
    	DISPLAY_CACHE.put("[J", "long");
    	DISPLAY_CACHE.put("Z", "boolean");
    	DISPLAY_CACHE.put("[Z", "boolean[]");
    	DISPLAY_CACHE.put("S", "short");
    	DISPLAY_CACHE.put("[S", "short[]");
    	DISPLAY_CACHE.put("F", "float");
    	DISPLAY_CACHE.put("[F", "float[]");
    	DISPLAY_CACHE.put("D", "double");
    	DISPLAY_CACHE.put("[D", "double[]");
    	DISPLAY_CACHE.put("C", "char");
    	DISPLAY_CACHE.put("[C", "char[]");
    	DISPLAY_CACHE.put("B", "byte");
    	DISPLAY_CACHE.put("[B", "byte[]");
    }

	private TypeUtil() {
    }

    public static boolean isFinal(int access) {
        return (Opcodes.ACC_FINAL & access) != 0;
    }

    public static boolean isStatic(int access) {
        return (Opcodes.ACC_STATIC & access) != 0;
    }

    public static boolean isProtected(int access) {
        return (Opcodes.ACC_PROTECTED & access) != 0;
    }

    public static boolean isPublic(int access) {
        return (Opcodes.ACC_PUBLIC & access) != 0;
    }

    public static boolean isAbstract(int access) {
        return (Opcodes.ACC_ABSTRACT & access) != 0;
    }
    
    public static boolean isInterface(int access) {
        return (Opcodes.ACC_INTERFACE & access) != 0;
    }

    public static boolean isPrivate(int access) {
        return (Opcodes.ACC_PRIVATE & access) != 0;
    }
    
    public static boolean isSynthetic(int access) {
        return (Opcodes.ACC_SYNTHETIC & access) != 0;
    }

    public static String getAccess(int access) {
        StringBuilder sb = new StringBuilder();
        
        if ( isFinal(access)) {
            sb.append( "final" );
        }

        if ( isAbstract(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "abstract" );
        }       

        if ( isPrivate(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "private" );
        }
        
        if ( isProtected(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "protected" );
        }

        if ( isPublic(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "public" );
        }

        if ( isStatic(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "static" );
        }

         if ( isInterface(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "interface" );
        }

        if ( isSynthetic(access)) {
            if ( sb.length() > 0 ) sb.append( " " );
            sb.append( "synthetic" );
        }
        
        return sb.toString();
   }
    
    /**
     * Calculate a display name for the given internal signature.
     */
    public static String toDisplayType(String typeName) {
    	String cachedType = DISPLAY_CACHE.get(typeName);
    	if(cachedType != null) {
    		return cachedType;
    	}
    	String display = typeName.replace('/','.');
    	if(display.startsWith("[")) {
    		display = display.substring(1) + "[]";
    	}
    	return display;
    }

	public static String getParams(MethodNode m) {
		List<ParameterNode> params = m.parameters;
		if (params == null || params.isEmpty())
			return "()";
		StringBuilder sb = new StringBuilder();
		for (ParameterNode p : params) {
			sb.append(p.name + ", ");
		}
		return '(' + sb.toString() + ')';
	}
    
}