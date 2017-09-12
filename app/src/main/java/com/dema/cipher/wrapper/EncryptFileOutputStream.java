package com.dema.cipher.wrapper;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

public class EncryptFileOutputStream extends FileOutputStream {
	
	private boolean isEncrypted = true;

	public EncryptFileOutputStream(File file) throws FileNotFoundException {
		super(file);
	}

	public EncryptFileOutputStream(File file, boolean append)
			throws FileNotFoundException {
		super(file, append);
		if (append) {
			try {
				checkEncrypt(file);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public EncryptFileOutputStream(FileDescriptor fd) {
		super(fd);
	}

	public EncryptFileOutputStream(String path, boolean append)
			throws FileNotFoundException {
		super(path, append);
		if (append) {
			try {
				checkEncrypt(new File(path));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	void checkEncrypt (File file) throws Exception {
		byte[] flag = new byte[4];
		FileInputStream fis = null;
			fis = new FileInputStream(file);
			fis.read(flag);
			if (!new String(flag).equals("SM4:")) {
				isEncrypted = false;
			}
			fis.close();
	}

	public EncryptFileOutputStream(String path) throws FileNotFoundException {
		super(path);
	}

	@Override
	public void close() throws IOException {
		super.close();
	}

	@Override
	public FileChannel getChannel() {
		return super.getChannel();
	}

	@Override
	public void write(byte[] buffer, int byteOffset, int byteCount)
			throws IOException {
		if (isEncrypted) {
			int tmplen = FileUtil.D2Elength(byteCount);
			byte[] Dcontent = new byte[tmplen];
			byte[] Econtent = new byte[tmplen];
			System.arraycopy(buffer, byteOffset, Dcontent, 0, byteCount);
			byte[] bytelen = TypeConverHelper.intToBytes(byteCount);
			SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
			super.write(bytelen);
			buffer = Econtent;
			byteCount = tmplen;
		}
		super.write(buffer, byteOffset, byteCount);
	}

	@Override
	public void write(int oneByte) throws IOException {
		write(new byte[] { (byte) oneByte }, 0, 1);
	}

	@Override
	public void write(byte[] buffer) throws IOException {
		write(buffer, 0, buffer.length);
	}
}
