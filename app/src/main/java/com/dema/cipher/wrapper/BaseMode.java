package com.dema.cipher.wrapper;


public interface BaseMode {
	public abstract boolean isEncrypt();
	public abstract BaseChannelMode getFileChannelMode();
}
