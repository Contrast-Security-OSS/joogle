package com.contrastsecurity.joogle;

import java.util.LinkedList;
import java.util.List;

public abstract class AbstractMatch {

	protected boolean matched;
	protected List<String> evidence;
	
	public AbstractMatch() {
		matched = false;
		evidence = new LinkedList<String>();
	}
		
	public boolean matched() {
		return matched;
	}

	public void matched(boolean b) {
		this.matched = b;
	}
	
	public void evidence(String s) {
		evidence.add(s);
	}
	
	public List<String> evidence() {
		return evidence;
	}

	public boolean hasEvidence() {
		return evidence != null && !evidence.isEmpty();
	}
}
