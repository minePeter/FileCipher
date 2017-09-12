package com.dema.cipher.wrapper;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class FileStreamEncryptMode implements BaseMode {
	
	private FileOutputStream mFs;
	
	private File mFile;
	private String mPath;
	private boolean mAppend;
	private FileDescriptor mFd;
	private String mName;
	private int mMode;

	private RandomAccessFile mRaf;

	private byte[] mCurrentDecryptBytes = new byte[0]; // 所在分段明文数组
	private long mStartPosition = 4l; // 文件指针所在分段的密文起始位置
	private int mCurrentStartPosition = 0; // 文件指针所在分段的明文未读取部分的起始位置
	private int mPosition = 0; // 文件指针所在明文位置
	private boolean mIsEncrypted = false;

	private FileChannelMode mFcm;
	
	@Override
	public boolean isEncrypt() {
		return mIsEncrypted;
	}

	@Override
	public BaseChannelMode getFileChannelMode() {
		return mFcm;
	}
	/**
	 * 根据流前4位判断是否已加密（不排除存在以SM4:开头的未加密明文）
	 */
	private void checkEncrypt() {

		byte[] flag = new byte[4];
		try {
			mRaf.seek(0);
			mRaf.read(flag);
			if (new String(flag).equals("SM4:")) {
				mIsEncrypted = true;
			} else {
				if(mRaf.length() == 0) {
					mRaf.write("SM4:".getBytes());
					mIsEncrypted = true;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void setFileOutputStream(FileOutputStream fos) {
		this.mFs = fos;
		try {
			fos.write("SM4:".getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void write(int oneByte) throws IOException {
        write(new byte[] { (byte) oneByte }, 0, 1);
    }
	
	public void write(byte[] buffer) throws IOException {
		write(buffer, 0, buffer.length);
	}
	
	public void write(byte[] buffer, int byteOffset, int byteCount) throws IOException {

		int length = byteCount - byteOffset;
		
		int tmplen = 0;
		byte[] Econtent = null;
		byte[] Dcontent = null;
		byte[] bytelen = null;
		
		if(mRaf.getFilePointer() == mRaf.length()) {
			tmplen = FileUtil.D2Elength(length);
			Econtent = new byte[tmplen];
			Dcontent = new byte[tmplen];
			System.arraycopy(buffer, byteOffset, Dcontent, 0, byteCount);
			bytelen = TypeConverHelper.intToBytes(length);
			SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
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
				tmplen = FileUtil.D2Elength(len);
				Dcontent = new byte[tmplen];
				Econtent = new byte[tmplen];
				
				if(mRaf.read(Econtent) == tmplen) {
					SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
					if(length < len) {
						int t = length - offset;
						System.arraycopy(buffer, offset, Dcontent, mCurrentStartPosition, t);
						SMS4.getSMS4Instance().sms4(Dcontent, tmplen, SMS4.key, Econtent, SMS4.ENCRYPT);
						mRaf.seek(mStartPosition);
						headByte = TypeConverHelper.intToBytes(len);
						mRaf.write(headByte);
						mRaf.write(Econtent);
						mCurrentDecryptBytes = new byte[len];
						System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
						mCurrentStartPosition = t;
						mPosition += length;
						break;
					} else {
						System.arraycopy(buffer, offset, Dcontent, mCurrentStartPosition, len);
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
	}
	
	public FileChannel getChannel() {
		FileChannel fileChannel = mRaf.getChannel();
		mFcm = new FileChannelMode(fileChannel);
		return fileChannel;
	}

	private long seek(long position) {
		byte[] flag = new byte[4];
		long Eposition = 0;
		try {
			mRaf.read(flag);
			if (!new String(flag).equals("SM4:")) {
				mRaf.seek(position);
				return position;
			}
			Eposition += 4;
			while (position > 0) {
				byte[] head = new byte[4];
				mStartPosition = mRaf.getFilePointer();
				if (mRaf.read(head) != 4) {
					Eposition += position;
					return Eposition;
				}
				Eposition += 4;
				int len = TypeConverHelper.bytesToInt(head);
				int tmplen = FileUtil.D2Elength(len);
				if (position < len) {
					Eposition += position;
					return Eposition;
				} else {
					Eposition += tmplen;
					mRaf.skipBytes(tmplen);
				}
				position -= len;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return 0;
	}
	
	private long seek(RandomAccessFile raf, long position) {
		System.out.println("-------------seek---------------");
		byte[] flag = new byte[4];
		long Eposition = 0;
		try {
			raf.read(flag);
			if (!new String(flag).equals("SM4:")) {
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
	class FileChannelMode implements BaseChannelMode {
		
		private FileChannel mFileChannel;
		private FileChannel mRafFileChannel;
		private long mPositionChannel;

		public FileChannelMode(FileChannel fileChannel) {
			mRafFileChannel = mRaf.getChannel();
			mPositionChannel = mPosition; 
		}

		public FileLock lock() throws IOException {
			return mFileChannel.lock();
		}

		public FileLock lock(long position, long size, boolean shared)
				throws IOException {
			return mFileChannel.lock(position, size, shared);
		}

		public MappedByteBuffer map(FileChannel.MapMode mode, long position,
				long size) throws IOException {
			return mFileChannel.map(mode, position, size);
		}

		public long position() throws IOException {
			return mPositionChannel;
		}

		public FileChannel position(long offset) throws IOException {
			long Eposition = seek(offset);
			byte[] head = new byte[4];
			if(mRaf.read(head)!=4) {//文件结束仍不够
				return mRafFileChannel;//明文读取在本次已读完，返回可读取长度
			}
			int len = TypeConverHelper.bytesToInt(head);
			// 获取密文实际长度（包括补位）
			int tmplen = FileUtil.D2Elength(len);
			byte[] Econtent = new byte[tmplen];
			byte[] Dcontent = new byte[tmplen];
			if(mRaf.read(Econtent) == tmplen) {
				SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key,
						Dcontent, SMS4.DECRYPT);
				mCurrentDecryptBytes = new byte[len];
				System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
				mCurrentStartPosition = len - (int)(mRaf.getFilePointer() - Eposition);
			}
			return mRafFileChannel.position(Eposition);
		}
		
		public int write(ByteBuffer src) throws IOException {
			System.out.println("---------------------write----------------------");
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
	    	System.out.println("---------------------write----------------------");
			RandomAccessFile raf = new RandomAccessFile(mFile, "rw");
			long Eposition = seek(raf, position);
	    	int length = src.limit();
			byte[] outBuffer = new byte[length];
			src.get(outBuffer);
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
	    	for(int i = offset;i - offset < length; i++) {
	    		n += write(buffers[i]);
	    	}
	    	return n;
	    }
	    
		public long size() throws IOException {
			return mFileChannel.size();
		}

		public long transferFrom(ReadableByteChannel src, long position,
				long count) throws IOException {
			return mFileChannel.transferFrom(src, position, count);
		}

		public long transferTo(long position, long count,
				WritableByteChannel target) throws IOException {
			return mFileChannel.transferTo(position, count, target);
		}

		public FileChannel truncate(long size) throws IOException {
			return mFileChannel.truncate(size);
		}

		@Override
		public int read(ByteBuffer buffer) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int read(ByteBuffer buffer, long position) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long read(ByteBuffer[] buffers) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long read(ByteBuffer[] buffers, int start, int number)
				throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}
	}
	
	
	public FileStreamEncryptMode(File file) {
		this.mFile = file;
		try {
			mRaf = new RandomAccessFile(file, "rw");
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	public FileStreamEncryptMode(File file, boolean append) {
		this.mFile = file;
		this.mAppend = append;
		try {
			mRaf = new RandomAccessFile(file, "rw");
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	public FileStreamEncryptMode(FileDescriptor fd) {
		this.mFd = fd;
	}
	
	public FileStreamEncryptMode(String path) {
		this.mPath = path;
		try {
			mRaf = new RandomAccessFile(path, "rw");
			mFile = new File(path);
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	public FileStreamEncryptMode(String path, boolean append) {
		this.mPath = path;
		this.mAppend = append;
		try {
			mRaf = new RandomAccessFile(path, "rw");
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	public FileStreamEncryptMode(String name, int mode) {
		this.mName = name;
		this.mMode = mode;
		try {
			mRaf = new RandomAccessFile(name, "rw");
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public void close() throws IOException{
		mRaf.close();
	}

}
