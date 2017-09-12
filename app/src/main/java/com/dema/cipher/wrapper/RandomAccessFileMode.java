package com.dema.cipher.wrapper;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class RandomAccessFileMode implements BaseMode {

	private RandomAccessFile mRaf;
	private String mFileName;
	private String mMode;
	private File mFile;

	private byte[] mCurrentDecryptBytes = new byte[0]; // 所在分段明文数组
	private long mStartPosition = 4l; // 文件指针所在分段的密文起始位置
	private int mCurrentStartPosition = 0; // 文件指针所在分段的明文未读取部分的起始位置
	private long mFileLength = 0l;
	private long mPosition = 0l; // 文件指针所在明文位置

	public FileChannelMode mFcm;

	private final byte[] scratch = new byte[8];

	private boolean mIsEncrypted = false;

	public void seek(long offset) throws IOException {
		mRaf.seek(4);
		mPosition = 0;
		mStartPosition = 4;
		mCurrentDecryptBytes = new byte[0];
		mCurrentStartPosition = 0;
		skipBytes((int) offset);
	}

	public int skipBytes(int count) throws IOException {
		System.out.println("-------------skipBytes--------------");
		long length = length();
		if (length < mPosition) {
			mCurrentDecryptBytes = new byte[0];
			mPosition = length;
			return count;
		}
		length = mCurrentDecryptBytes.length - mCurrentStartPosition;
		if(length >= count) {
			// case:当前明文长度足够
			mCurrentStartPosition += count;
		} else {
			// case:当前明文数组长度不足
			while (length < count) {
				mStartPosition = mRaf.getFilePointer();
				byte[] head = new byte[4];
				if (mRaf.read(head) != 4) {
					mCurrentDecryptBytes = new byte[0];
					mPosition = length;
					return count;
				}
				int len = TypeConverHelper.bytesToInt(head);
				length += len;
				int tmplen = FileUtil.D2Elength(len);
				if (length < count) {
					// 不解密，直接跳过
					mRaf.skipBytes(tmplen);
				} else {
					// skip的position刚好处于该段中
					byte[] Econtent = new byte[tmplen];
					byte[] Dcontent = new byte[tmplen];
					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
								Dcontent, SMS4.DECRYPT);
						int offset = (int) (count - length + len);
						mCurrentDecryptBytes = new byte[len];
						System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
						mCurrentStartPosition = offset;
						Econtent = Dcontent = null;
					} else {
						break;
					}
				}

			}
		}
		mPosition += count;
		return count;
	}

	public long getFilePointer() {
		return mPosition;
	}

	public long length() throws IOException {
		System.out.println("-------------length--------------");
		long fileLength = 0;
		FileInputStream lengthStream = null;
		try {
			lengthStream = new FileInputStream(mFile);
			byte[] flag = new byte[4];
			lengthStream.read(flag);
			String strFlag = new String(flag);
			if (!strFlag.equals("SM4:")) {
				fileLength = lengthStream.available();
				mFileLength = fileLength;
				return mFileLength;
			}
			byte[] head = new byte[4];
			while (lengthStream.read(head) != -1) {
				int len = TypeConverHelper.bytesToInt(head);
				int tmplen = FileUtil.D2Elength(len);
				fileLength += len;
				lengthStream.skip(tmplen);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				lengthStream.close();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		mFileLength = fileLength;
		return mFileLength;
	}

	public void close() {
		try {
			mRaf.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int read() throws IOException {
		return (read(scratch, 0, 1) != -1) ? scratch[0] & 0xff : -1;
	}

	public int read(byte[] buffer) throws IOException {
		System.out.println("-------------read--------------");
		return read(buffer, 0, buffer.length);
	}

	public int read(byte[] buffer, int byteOffset, int byteCount)
			throws IOException {
		if (mRaf.getFilePointer() == mRaf.length()
				&& (mCurrentDecryptBytes == null || mCurrentDecryptBytes.length == 0)) {
			return -1;
		}
		int ret = 0;
		int needLen = byteCount - byteOffset;
		int length = mCurrentDecryptBytes.length - mCurrentStartPosition;
		System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, buffer,
				byteOffset, length < needLen ? length : needLen);
		if (length >= needLen) {
			ret = needLen;
			mPosition += needLen;
			mCurrentStartPosition += needLen;
			needLen = 0;
		} else {
			needLen -= length;
			byteOffset += length;
			while (needLen > 0) {
				mStartPosition = mRaf.getFilePointer();
				byte[] head = new byte[4];
				// 结束
				if (mRaf.read(head) != 4) {
					ret = length;
					mCurrentDecryptBytes = new byte[0];
					mCurrentStartPosition = 0;
					break;
				} else {
					int len = TypeConverHelper.bytesToInt(head);
					// 获取密文实际长度（包括补位）
					int tmplen = FileUtil.D2Elength(len);
					byte[] Econtent = new byte[tmplen];
					byte[] Dcontent = new byte[tmplen];
					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
								Dcontent, SMS4.DECRYPT);
						if (len < needLen) {
							System.arraycopy(Dcontent, 0, buffer, byteOffset,
									len);
							byteOffset += len;
							needLen -= len;
							mPosition += len;
							ret += len;
						} else {
							System.arraycopy(Dcontent, 0, buffer, byteOffset,
									needLen);
							mCurrentDecryptBytes = new byte[len];
							System.arraycopy(Dcontent, 0, mCurrentDecryptBytes,
									0, len);
							mCurrentStartPosition = needLen;
							mPosition += needLen;
							ret += needLen;
							needLen = 0;
						}
					} else {
						break;
					}
				}
			}
		}
		return ret;
	}

	public final boolean readBoolean() throws IOException {
		int temp = this.read();
		if (temp < 0) {
			throw new EOFException();
		}
		return temp != 0;
	}

	public final byte readByte() throws IOException {
		int temp = this.read();
		if (temp < 0) {
			throw new EOFException();
		}
		return (byte) temp;
	}

	public final char readChar() throws IOException {
		return (char) readShort();
	}

	public final double readDouble() throws IOException {
		return Double.longBitsToDouble(readLong());
	}

	public final float readFloat() throws IOException {
		return Float.intBitsToFloat(readInt());
	}

	public final void readFully(byte[] dst) throws IOException {
		readFully(dst, 0, dst.length);
	}

	private boolean checkOffsetAndCount(int arrayLength, int offset, int count) {
		if ((offset | count) < 0 || offset > arrayLength
				|| arrayLength - offset < count) {
			return false;
		}
		return true;
	}

	public final void readFully(byte[] dst, int offset, int byteCount)
			throws IOException {
		if (!checkOffsetAndCount(dst.length, offset, byteCount)) {
			throw new ArrayIndexOutOfBoundsException();
		}
		while (byteCount > 0) {
			int result = read(dst, offset, byteCount);
			if (result < 0) {
				throw new EOFException();
			}
			offset += result;
			byteCount -= result;
		}
	}

	public final int readInt() throws IOException {
		readFully(scratch, 0, 4);
		return TypeConverHelper.bytesToInt(scratch);
	}

	public final String readLine() throws IOException {
		StringBuilder line = new StringBuilder(80); // Typical line length
		boolean foundTerminator = false;
		long unreadPosition = 0;
		while (true) {
			int nextByte = read();
			switch (nextByte) {
			case -1:
				return line.length() != 0 ? line.toString() : null;
			case 13:
				if (foundTerminator) {
					seek(unreadPosition);
					return line.toString();
				}
				foundTerminator = true;
				/* Have to be able to peek ahead one byte */
				unreadPosition = getFilePointer();
				break;
			case 10:
				return line.toString();
			default:
				if (foundTerminator) {
					seek(unreadPosition);
					return line.toString();
				}
				line.append((char) nextByte);
			}
		}
	}

	public final long readLong() throws IOException {
		readFully(scratch, 0, 8);
		return (long) TypeConverHelper.bytesToDouble(scratch);
	}

	public final short readShort() throws IOException {
		readFully(scratch, 0, 4);
		return (short) TypeConverHelper.bytesToInt(scratch);
	}

	public final int readUnsignedByte() throws IOException {
		int temp = this.read();
		if (temp < 0) {
			throw new EOFException();
		}
		return temp;
	}

	public final int readUnsignedShort() throws IOException {
		return ((int) readShort()) & 0xffff;
	}

	public final String readUTF() throws IOException {
		int utfSize = readUnsignedShort();
		if (utfSize == 0) {
			return "";
		}
		byte[] buf = new byte[utfSize];
		if (read(buf, 0, buf.length) != buf.length) {
			throw new EOFException();
		}
		return new String(buf, "utf-8");
	}

	public void write(byte[] buffer) throws IOException {
		write(buffer, 0, buffer.length);
	}

	public void write(byte[] buffer, int byteOffset, int byteCount)
			throws IOException {
		int len = byteCount;
		byte[] Econtent = null;
		byte[] Dcontent = null;
		if (mRaf.getFilePointer() == mRaf.length()) {
			int tmplen = FileUtil.D2Elength(len);
			Dcontent = new byte[tmplen];
			Econtent = new byte[tmplen];
			System.arraycopy(buffer, byteOffset, Dcontent, 0, byteCount);
			SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
			byte bytelen[] = TypeConverHelper.intToBytes(len);
			mRaf.write(bytelen);
			mRaf.write(Econtent);
			mStartPosition += tmplen;
//			mFileLength += len;
			mPosition += len;
		} else {
			int length = byteCount;
			mRaf.seek(mStartPosition);
			int tmplen = 0;
			while (length > 0) {
				mStartPosition = mRaf.getFilePointer();
				byte[] head = new byte[4];
				// 结束
				if (mRaf.read(head) != 4) {
					len = length;
					tmplen = FileUtil.D2Elength(len);
					Dcontent = new byte[tmplen];
					System.arraycopy(buffer, byteOffset, Dcontent, 0, length);
					Econtent = new byte[tmplen];
					SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key,
							Econtent, SMS4.ENCRYPT);
					byte bytelen[] = TypeConverHelper.intToBytes(len);
					mRaf.write(bytelen);
					mRaf.write(Econtent);
					mStartPosition += tmplen;
//					mFileLength += length;
					mPosition += length;
					break;
				} else {//当前分段先解密
					len = TypeConverHelper.bytesToInt(head);
					// 获取密文实际长度（包括补位）
					tmplen = FileUtil.D2Elength(len);
					Econtent = new byte[tmplen];
					Dcontent = new byte[tmplen];
					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
								Dcontent, SMS4.DECRYPT);
						
						tmplen = length < len ? length : len;
						System.arraycopy(buffer, byteOffset, Dcontent, 0, tmplen);
						SMS4.getSMS4Instance().sms4(Dcontent, Dcontent.length,
								SMS4.key, Econtent, SMS4.ENCRYPT);
						mRaf.seek(mStartPosition + 4);
						mRaf.write(Econtent);
						byteOffset += len;
						length -= tmplen;
						mPosition += tmplen;
					} else {
						break;
					}
				}
			}
			mStartPosition = mRaf.getFilePointer();
			mCurrentDecryptBytes = new byte[len];
			System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
			mCurrentStartPosition = tmplen;
		}
	}

	public void write(int oneByte) throws IOException {
		scratch[0] = (byte) (oneByte & 0xff);
		write(scratch, 0, 1);
	}

	public final void writeBoolean(boolean val) throws IOException {
		write(val ? 1 : 0);
	}

	public final void writeByte(int val) throws IOException {
		write(val & 0xFF);
	}

	public final void writeBytes(String str) throws IOException {
		byte[] bytes = new byte[str.length()];
		for (int index = 0; index < str.length(); index++) {
			bytes[index] = (byte) (str.charAt(index) & 0xFF);
		}
		write(bytes);
	}

	public final void writeChar(int val) throws IOException {
		writeShort(val);
	}

	public final void writeChars(String str) throws IOException {
		write(str.getBytes("UTF-16BE"));
	}

	public final void writeDouble(double val) throws IOException {
		writeLong(Double.doubleToLongBits(val));
	}

	public final void writeFloat(float val) throws IOException {
		writeInt(Float.floatToIntBits(val));
	}

	public final void writeInt(int val) throws IOException {
		byte[] sr = TypeConverHelper.intToBytes(val);
		write(sr);
	}

	public final void writeLong(long val) throws IOException {
		byte[] sr = TypeConverHelper.intToBytes((int) val);
		write(sr);
	}

	public final void writeShort(int val) throws IOException {
		byte[] sr = TypeConverHelper.intToBytes(val);
		write(sr);
	}

	public final void writeUTF(String str) throws IOException {
		write(str.getBytes("utf-8"));
	}

	/**
	 * 返回当前流是否加密
	 * 
	 * @return
	 */
	public boolean isEncrypt() {
		return mIsEncrypted;
	}

	/**
	 * 根据流前4位判断是否已加密（不排除存在以SM4:开头的未加密明文）
	 */
	private void checkEncrypt() {

		byte[] flag = new byte[4];
		try {
			if (mRaf.length() == 0) {
				mRaf.write("SM4:".getBytes());
				mStartPosition = 4l;
				mIsEncrypted = true;
				return;
			}
			mRaf.read(flag);
			String strFlag = new String(flag);
			if (strFlag.equals("SM4:")) {
				mIsEncrypted = true;
				mStartPosition = 4l;
			} else {
				mRaf.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private long D2EPosition(long position) {
		long Eposition = 0;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(mFile, "r");
			byte[] flag = new byte[4];
			raf.read(flag);
			String strFlag = new String(flag);
			if (!strFlag.equals("SM4:")) {
				return position;
			}
			while(position > 0) {
				byte[] head = new byte[4];
				raf.read(head);
				int len = TypeConverHelper.bytesToInt(head);
				int tmplen = FileUtil.D2Elength(len);
				if (position < len) {
					Eposition += position;
				} else {
					Eposition += tmplen;
				}
				position -= len;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				raf.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return Eposition;
	}
	
	private long seek(RandomAccessFile raf, long position) {
		byte[] flag = new byte[4];
		long Eposition = 0;
		try {
			raf.read(flag);
			String strFlag = new String(flag);
			if (!strFlag.equals("SM4:")) {
				raf.seek(position);
				return position;
			}
			Eposition += 4;
			while (position > 0) {
				byte[] head = new byte[4];
				if (raf.read(head) != 4) {
					Eposition += position;
					return Eposition;
				}
				Eposition += 4;
				int len = TypeConverHelper.bytesToInt(head);
				int tmplen = FileUtil.D2Elength(len);
				if (position < len) {
					Eposition += position;
					mRaf.seek(mRaf.getFilePointer() - 4);
					return Eposition;
				} else {
					Eposition += tmplen;
					raf.skipBytes(tmplen);
				}
				position -= len;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return 0;
	}
	
	public FileChannel getChannel() {
		FileChannel fileChannel = mRaf.getChannel();
		mFcm = new FileChannelMode(fileChannel);
		return fileChannel;
	}

	public class FileChannelMode implements BaseChannelMode {

		private FileChannel mFileChannel;

		public FileChannelMode(FileChannel fileChannel) {
			mFileChannel = fileChannel;
		}

		public int write(ByteBuffer src) throws IOException {
			int length = src.limit();
			byte[] outBuffer = new byte[length];
			src.get(outBuffer);
			if (mRaf.getFilePointer() == mRaf.length()) {
				int tmplen = FileUtil.D2Elength(length);
				byte[] Econtent = new byte[tmplen];
				byte[] Dcontent = new byte[tmplen];
				System.arraycopy(outBuffer, 0, Dcontent, 0, length);
				byte[] bytelen = TypeConverHelper.intToBytes(length);
				SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key,
						Econtent, SMS4.ENCRYPT);
				mPosition += length;
				mStartPosition = mRaf.getFilePointer();
				mRaf.write(bytelen);
				mRaf.write(Econtent);
			} else {
				mRaf.seek(mStartPosition);
				int offset = 0;
				while (length > offset) {
					byte[] headByte = new byte[4];
					mStartPosition = mRaf.getFilePointer();
					mRaf.read(headByte);
					int len = TypeConverHelper.bytesToInt(headByte);
					int tmplen = FileUtil.D2Elength(len);
					byte[] Dcontent = new byte[tmplen];
					byte[] Econtent = new byte[tmplen];

					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
								Dcontent, SMS4.DECRYPT);
						if (length < len) {
							int t = length - offset;
							System.arraycopy(outBuffer, offset, Dcontent, mCurrentStartPosition, t);
							SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
							mRaf.seek(mStartPosition);
							headByte = TypeConverHelper.intToBytes(len);
							mRaf.write(headByte);
							mRaf.write(Econtent);
							mCurrentDecryptBytes = new byte[len];
							System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
							mCurrentStartPosition = t;
							mPosition += length;
							return length;
						} else {
							System.arraycopy(outBuffer, offset, Dcontent, mCurrentStartPosition, len);
							SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
							mRaf.seek(mStartPosition);
							headByte = TypeConverHelper.intToBytes(len);
							mRaf.write(headByte);
							mRaf.write(Econtent);
							mCurrentStartPosition = 0;
							offset += len;
						}

					} else {
						break;
					}

				}
			}
			return 0;
		}

	    public int write(ByteBuffer src, long position)
	            throws IOException {
			int length = src.limit();
			byte[] outBuffer = new byte[length];
			src.get(outBuffer);
			RandomAccessFile raf = new RandomAccessFile(mFile, "rw");
			long Eposition = seek(raf, position);
			if (Eposition == raf.length()) {
				raf.seek(Eposition);
				int tmplen = FileUtil.D2Elength(length);
				byte[] Econtent = new byte[tmplen];
				byte[] Dcontent = new byte[tmplen];
				System.arraycopy(outBuffer, 0, Dcontent, 0, length);
				byte[] bytelen = TypeConverHelper.intToBytes(length);
				SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
				raf.write(bytelen);
				raf.write(Econtent);
			} else {
				int currentStartPosition = (int)(Eposition - raf.getFilePointer());
				int offset = 0;
				while (length > offset) {
					byte[] headByte = new byte[4];
					raf.read(headByte);
					int len = TypeConverHelper.bytesToInt(headByte);
					int tmplen = FileUtil.D2Elength(len);
					byte[] Dcontent = new byte[tmplen];
					byte[] Econtent = new byte[tmplen];
					if (raf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
						if (length < len) {
							int t = length - offset;
							System.arraycopy(outBuffer, offset, Dcontent, currentStartPosition, t);
							SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
							headByte = TypeConverHelper.intToBytes(len);
							raf.write(headByte);
							raf.write(Econtent);
							return length;
						} else {
							System.arraycopy(outBuffer, offset, Dcontent, currentStartPosition, len);
							SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
							headByte = TypeConverHelper.intToBytes(len);
							raf.write(headByte);
							raf.write(Econtent);
							currentStartPosition = 0;
							offset += len;
						}
					} else {
						break;
					}

				}
			}
			return 0;
	    }

		public final long write(ByteBuffer[] buffers) throws IOException {
			return write(buffers, 0, buffers.length);
		}

		public final long write(ByteBuffer[] buffers, int offset, int length)
				throws IOException {
			long n = 0;
			for (int i = offset; i - offset < length; i++) {
				n += write(buffers[i]);
			}
			return n;
		}
		
		public FileLock lock()
				throws IOException {
			return lock(0L, Long.MAX_VALUE, false);
		}

		public FileLock lock(long position, long size, boolean shared)
				throws IOException {
			long Eposition = D2EPosition(position);
			long Esize = D2EPosition(position + size) - Eposition;
			return mFileChannel.lock(Eposition, Esize, shared);
		}

		public MappedByteBuffer map(FileChannel.MapMode mode, long position,
				long size) throws IOException {
			long Eposition = D2EPosition(position);
			long Esize = D2EPosition(position + size) - Eposition;
			return mFileChannel.map(mode, Eposition, Esize);
		}

		public long position() throws IOException {
			return mPosition;
		}

		public FileChannel position(long offset) throws IOException {
			seek(offset);
			return mFileChannel.position(offset);
		}

		//读取会影响到依赖的流
		public int read(ByteBuffer buffer) throws IOException {
			int needLen = buffer.limit();
			byte[] readBytes = new byte[needLen];
			int byteOffset = 0;
			int length = mCurrentDecryptBytes.length - mCurrentStartPosition;// 可用明文长度
			if (length >= needLen) {
				System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, readBytes, byteOffset, needLen);
				mCurrentStartPosition += needLen;
				mPosition += needLen;
				buffer.put(readBytes);
				return needLen;//当前明文满足本次读取
			} else {
				mRaf.seek(mStartPosition);
				System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, readBytes, byteOffset, length);
				mPosition += length;
				byteOffset += length;
				byte[] head = new byte[4];
				int len = 0;
				int tmplen = 0;
				if(mCurrentDecryptBytes.length > 0) {
					mRaf.read(head);
					len = TypeConverHelper.bytesToInt(head);
					// 获取密文实际长度（包括补位）
					tmplen = FileUtil.D2Elength(len);
					mRaf.skipBytes(tmplen);
				}
				while (length < needLen) {// 可用明文长度小于需要
					head = new byte[4];
					mStartPosition = mRaf.getFilePointer();
					if(mRaf.read(head)!=4) {//文件结束仍不够
						byte[] newReadBytes = new byte[length];
						System.arraycopy(readBytes, 0, newReadBytes, 0, length);
						buffer.put(newReadBytes);
						return length;//明文读取在本次已读完，返回可读取长度
					}
					len = TypeConverHelper.bytesToInt(head);
					// 获取密文实际长度（包括补位）
					tmplen = FileUtil.D2Elength(len);
					byte[] Econtent = new byte[tmplen];
					byte[] Dcontent = new byte[tmplen];
					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
								Dcontent, SMS4.DECRYPT);
						length += len;
						if (length < needLen) {// 可用明文长度仍小于需要
							System.arraycopy(Dcontent, 0, readBytes, byteOffset, len);
							byteOffset += len;
							mPosition += len;
						} else {// 可用明文长度已满足需要
							mCurrentStartPosition = needLen - length + len;// 最新明文段需要被读取长度
							System.arraycopy(Dcontent, 0, readBytes, byteOffset, mCurrentStartPosition);
							mCurrentDecryptBytes = new byte[len];
							System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
							mPosition += mCurrentStartPosition;
							buffer.put(readBytes);
							return needLen;//正常读取结束
						}
						Econtent = Dcontent = null;
					} else {
						break;
					}
				}
			}
			buffer.put(readBytes);
			return 0;
		}

		public int read(ByteBuffer buffer, long position) throws IOException {
			int needLen = buffer.limit();
			byte[] readBytes = new byte[needLen];
			int byteOffset = 0;
			RandomAccessFile raf = new RandomAccessFile(mFile, "r");
			long Eposition = seek(raf, position);
			int currentStartPosition = (int)(Eposition - raf.getFilePointer());
			
			if(raf.length() <= Eposition) {
				raf.close();
				return -1;
			}
			byte[] head = new byte[4];
			if(raf.read(head)!=4) {//文件结束仍不够
				raf.close();
				return -1;//明文读取在本次已读完，返回可读取长度
			}
			int len = TypeConverHelper.bytesToInt(head);
			// 获取密文实际长度（包括补位）
			int tmplen = FileUtil.D2Elength(len);
			byte[] Econtent = new byte[tmplen];
			byte[] Dcontent = new byte[tmplen];
			if(raf.read(Econtent) == tmplen) {
				SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
				if(len - currentStartPosition < needLen) {
					System.arraycopy(Dcontent, currentStartPosition, readBytes, 0, len - currentStartPosition);
					byteOffset += len - currentStartPosition;
				} else {
					System.arraycopy(Dcontent, currentStartPosition, readBytes, 0, needLen);
					buffer.put(readBytes);
					raf.close();
					return needLen;
				}
			} else {
				buffer.put(readBytes);
				raf.close();
				return -1;
			}
			while(byteOffset < needLen) {
				head = new byte[4];
				if(raf.read(head)!=4) {//文件结束仍不够
					buffer.put(readBytes);
					raf.close();
					return -1;//明文读取在本次已读完，返回可读取长度
				}
				len = TypeConverHelper.bytesToInt(head);
				// 获取密文实际长度（包括补位）
				tmplen = FileUtil.D2Elength(len);
				Econtent = new byte[tmplen];
				Dcontent = new byte[tmplen];
				if(raf.read(Econtent) == tmplen) {
					SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
							Dcontent, SMS4.DECRYPT);
					if(byteOffset + len< needLen) {//本段全部加入返回结果
						System.arraycopy(Dcontent, 0, readBytes, byteOffset, len);
						byteOffset += len;
					} else {//
						System.arraycopy(Dcontent, 0, readBytes, byteOffset, needLen - byteOffset);
						buffer.put(readBytes);
						raf.close();
						return needLen;
					}
				} else {
					break;
				}
				
			}
			buffer.put(readBytes);
			raf.close();
			return -1;
		}

		public final long read(ByteBuffer[] buffers) throws IOException {
			return read(buffers, 0, buffers.length);
		}

		public long read(ByteBuffer[] buffers, int start, int number)
				throws IOException {
			long n = 0;
			for (int i = start; i - start < number; i++) {
				n += read(buffers[i]);
			}
			return n;
		}

		public long size() throws IOException {
			return RandomAccessFileMode.this.length();
		}

		public long transferFrom(ReadableByteChannel src, long position,
				long count) throws IOException {
			long Eposition = D2EPosition(position);
			long Ecount = D2EPosition(position + count) - Eposition;
			return mFileChannel.transferFrom(src, Eposition, Ecount);
		}

		public long transferTo(long position, long count,
				WritableByteChannel target) throws IOException {
			long Eposition = D2EPosition(position);
			long Ecount = D2EPosition(position + count) - Eposition;
			return mFileChannel.transferTo(Eposition, Ecount, target);
		}

		public FileChannel truncate(long size) throws IOException {
			return mFileChannel.truncate(size);
		}
		
	}
	
	public RandomAccessFileMode(String fileName, String mode)
			throws FileNotFoundException {
		this.mFileName = fileName;
		this.mMode = mode;
		mRaf = new RandomAccessFile(fileName, mode);
		this.mFile = new File(fileName);
		checkEncrypt();
	}

	public RandomAccessFileMode(File file, String mode)
			throws FileNotFoundException {
		this.mFile = file;
		this.mMode = mode;
		mRaf = new RandomAccessFile(file, mode);
		mFileName = file.getName();
		checkEncrypt();
	}

	@Override
	public FileChannelMode getFileChannelMode() {
		return mFcm;
	}
}
