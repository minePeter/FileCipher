package com.dema.cipher.wrapper;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class DecryptFileInputStream extends FileInputStream {

	private boolean isEncrypted = true;
	private int avilibale = 0;
	private byte[] currentDecryptBytes = new byte[0]; // 所在分段明文数组
	private int currentStartPosition = 0; // 文件指针所在分段的明文未读取部分的起始位置
	private int position = 0; // 文件指针所在明文位置

	public DecryptFileInputStream(File file) throws FileNotFoundException {
		super(file);
		try {
			checkEncrypt(new FileInputStream(file));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public DecryptFileInputStream(FileDescriptor fd) {
		super(fd);
		try {
			checkEncrypt(new FileInputStream(fd));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public DecryptFileInputStream(String path) throws FileNotFoundException {
		super(path);
		try {
			checkEncrypt(new FileInputStream(path));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	void checkEncrypt(FileInputStream fis) throws Exception {
		byte[] flag = new byte[4];
		fis.read(flag);
		if (!new String(flag).equals("SM4:")) {
			isEncrypted = false;
			byte[] head = new byte[4];
			while (fis.read(head) != -1) {
				int len = TypeConverHelper.bytesToInt(head);
				avilibale += len;
				int tmplen = FileUtil.D2Elength(len);
				fis.skip(tmplen);
			}
		}
		fis.close();
	}

	@Override
	public int available() throws IOException {
		if (isEncrypted) {
			return this.avilibale;
		}
		return super.available();
	}

	@Override
	public int read() throws IOException {
		if (isEncrypted) {
			byte buffer[] = new byte[1];
			read(buffer);
			return buffer[0];
		}
		return super.read();
	}

	@Override
	public int read(byte[] buffer, int byteOffset, int byteCount)
			throws IOException {
		if (isEncrypted) {
			int length = 0;
			int len = currentDecryptBytes.length - currentStartPosition;
			if(len > byteCount) {
				System.arraycopy(currentDecryptBytes, currentStartPosition, buffer, byteOffset, byteCount);
				currentStartPosition += byteCount;
				avilibale -= byteCount;
				position += byteCount;
				return byteCount;
			} else {
				System.arraycopy(currentDecryptBytes, currentStartPosition, buffer, byteOffset, len);
				length += len;
				avilibale -= len;
				byteOffset += len;
				currentStartPosition = 0;
				currentDecryptBytes = new byte[0];
				while (length < byteCount) {
					byte[] head = new byte[4];
					if(super.read(head)!=4) {//文件结束仍不够
						return length;//明文读取在本次已读完，返回可读取长度
					}
					len = TypeConverHelper.bytesToInt(head);
					// 获取密文实际长度（包括补位）
					int tmplen = FileUtil.D2Elength(len);
					byte[] Econtent = new byte[tmplen];
					byte[] Dcontent = new byte[tmplen];
					if (super.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
						length += len;
						if (length < byteCount) {// 可用明文长度仍小于需要
							System.arraycopy(Dcontent, 0, buffer, byteOffset, len);
							byteOffset += len;
							avilibale -= len;
							position += len;
						} else {// 可用明文长度已满足需要
							currentStartPosition = byteCount - length + len;// 最新明文段需要被读取长度
							System.arraycopy(Dcontent, 0, buffer, byteOffset, currentStartPosition);
							currentDecryptBytes = new byte[len];
							System.arraycopy(Dcontent, 0, currentDecryptBytes, 0, len);
							avilibale -= currentStartPosition;
							position += currentStartPosition;
							return byteCount;//正常读取结束
						}
						Econtent = Dcontent = null;
					} else {
						break;
					}
				}
			}
		}
		return super.read(buffer, byteOffset, byteCount);
	}

	@Override
	public long skip(long byteCount) throws IOException {
		if (isEncrypted) {
			long ret = byteCount;
			if (avilibale < byteCount) {
				avilibale = 0;
//				position = (int)length();
				return byteCount;//skip超过范围
			}
			position += byteCount;
			int length = currentDecryptBytes.length - currentStartPosition;
			
			if(length >= byteCount) {
				currentStartPosition += (int) byteCount;
				avilibale -= (int) byteCount;
				position += (int) byteCount;
				return byteCount;//skip在本段明文范围
			} else {// case:当前明文数组长度不足
				avilibale -= length;
				while (length < byteCount) {
					byte[] head = new byte[4];
					if(super.read(head)!=4) {//文件结束仍不够
						return byteCount;//明文读取在本次已读完
					}
					int len = TypeConverHelper.bytesToInt(head);
					length += len;
					int tmplen = FileUtil.D2Elength(len);
					if (length < byteCount) {
						// 不解密，直接跳过
						super.skip(tmplen);
						avilibale -= len;
						position += len;
					} else {
						// skip的position刚好处于该段中，解密并将position后的明文追加到decryptBytes
						byte[] Econtent = new byte[tmplen];
						byte[] Dcontent = new byte[tmplen];
						if (super.read(Econtent) == tmplen) {
							SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
							System.arraycopy(Dcontent, 0, currentDecryptBytes, 0, len);
							currentStartPosition = len - (length - (int) byteCount);
							avilibale -= currentStartPosition;
							Econtent = Dcontent = null;
							return byteCount;//明文读取在本次已读完
						} else {
							break;
						}
					}
				}
			}
		}
		return super.skip(byteCount);
	}

	@Override
	public void mark(int readlimit) {
		super.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		return super.markSupported();
	}

	@Override
	public int read(byte[] buffer) throws IOException {
		if (isEncrypted) {
			return read(buffer, 0, buffer.length);
		}
		return super.read(buffer);
	}

	@Override
	public synchronized void reset() throws IOException {
		super.reset();
	}

}
