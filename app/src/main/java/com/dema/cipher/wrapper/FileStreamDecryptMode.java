package com.dema.cipher.wrapper;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class FileStreamDecryptMode implements BaseMode {

//	private FileInputStream mFileDecryptStream;
	private File mFile;
	private String mPath;
	private FileDescriptor mFd;
	private int mAvilibale = 0;

	private RandomAccessFile mRaf;

	private byte[] mCurrentDecryptBytes = new byte[0]; // 所在分段明文数组
	private long mStartPosition = 4l; // 文件指针所在分段的密文起始位置
	private int mCurrentStartPosition = 0; // 文件指针所在分段的明文未读取部分的起始位置
	private int mPosition = 0; // 文件指针所在明文位置
	private boolean mIsEncrypted = false;

	private FileChannelMode mFcm;

	
	/**
	 * 根据流前4位判断是否已加密（不排除存在以SM4:开头的未加密明文）
	 */
	private void checkEncrypt() {
		byte[] flag = new byte[4];
		try {
			mRaf.read(flag);
			if (new String(flag).equals("SM4:")) {
				mIsEncrypted = true;
			} else {
				mRaf.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 返回当前流是否加密
	 * 
	 * @return
	 */
	public boolean isEncrypt() {
		return mIsEncrypted;
	}

	public int available() throws IOException {
		if (mAvilibale != 0) {
			return mAvilibale;
		}
		long length = length();
		mAvilibale = (int)length - mPosition;
		mAvilibale = mAvilibale < 0 ? 0 : mAvilibale;
		return mAvilibale;
	}
	
	private long length() {
		long length = 0;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(mFile, "r");
			raf.seek(4);
			byte[] head = new byte[4];
			while (raf.read(head) != -1) {
				int len = TypeConverHelper.bytesToInt(head);
				length += len;
				int tmplen = FileUtil.D2Elength(len);
				raf.skipBytes(tmplen);
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
		return length;
	}

	public long skip(long byteCount) throws IOException {
		long ret = byteCount;
		if (available() < byteCount) {
			mAvilibale = 0;
			mPosition = (int)length();
			return byteCount;//skip超过范围
		}
		mPosition += byteCount;
		int length = mCurrentDecryptBytes.length - mCurrentStartPosition;
		
		if(length >= byteCount) {
			mCurrentStartPosition += (int) byteCount;
			mAvilibale -= (int) byteCount;
			return byteCount;//skip在本段明文范围
		} else {// case:当前明文数组长度不足
			mAvilibale -= length;
			while (length < byteCount) {
				byte[] head = new byte[4];
				mStartPosition = mRaf.getFilePointer();
				if(mRaf.read(head)!=4) {//文件结束仍不够
					return byteCount;//明文读取在本次已读完
				}
				int len = TypeConverHelper.bytesToInt(head);
				length += len;
				int tmplen = FileUtil.D2Elength(len);
				if (length < byteCount) {
					// 不解密，直接跳过
					mRaf.skipBytes(tmplen);
					mAvilibale -= len;
				} else {
					// skip的position刚好处于该段中，解密并将position后的明文追加到decryptBytes
					byte[] Econtent = new byte[tmplen];
					byte[] Dcontent = new byte[tmplen];
					if (mRaf.read(Econtent) == tmplen) {
						SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
						System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
						mCurrentStartPosition = len - (length - (int) byteCount);
						mAvilibale -= mCurrentStartPosition;
						Econtent = Dcontent = null;
						return byteCount;//明文读取在本次已读完
					} else {
						break;
					}
				}
			}
		}
		
		return ret;
	}

	public int read(byte[] bytes) throws IOException {
		return read(bytes, 0, bytes.length);
	}

	public int read(byte[] bytes, int byteOffset, int byteCount)
			throws IOException {
		System.out.println("--------------read----------------");
		if (available() == 0) {
			return -1;//明文读取在上一次已读完
		}
		int length = mCurrentDecryptBytes.length - mCurrentStartPosition;// 可用明文长度
		if (length >= byteCount) {
			System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, bytes, byteOffset, byteCount);
			mCurrentStartPosition += byteCount;
			mAvilibale -= byteCount;
			mPosition += byteCount;
			return byteCount;//当前明文满足本次读取
		} else {
			mRaf.seek(mStartPosition);
			System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, bytes, byteOffset, length);
			mAvilibale -= length;
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
			
			while (length < byteCount) {// 可用明文长度小于需要
				mStartPosition = mRaf.getFilePointer();
				head = new byte[4];
				if(mRaf.read(head)!=4) {//文件结束仍不够
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
					if (length < byteCount) {// 可用明文长度仍小于需要
						System.arraycopy(Dcontent, 0, bytes, byteOffset, len);
						byteOffset += len;
						mAvilibale -= len;
						mPosition += len;
					} else {// 可用明文长度已满足需要
						mCurrentStartPosition = byteCount - length + len;// 最新明文段需要被读取长度
						System.arraycopy(Dcontent, 0, bytes, byteOffset, mCurrentStartPosition);
						mCurrentDecryptBytes = new byte[len];
						System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
						mAvilibale -= mCurrentStartPosition;
						mPosition += mCurrentStartPosition;
						return byteCount;//正常读取结束
					}
					Econtent = Dcontent = null;
				} else {
					break;
				}
			}
		}
		return -1;
	}

	public void close() {
		try {
			mRaf.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			mRaf.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private long seek(long position) {
		byte[] flag = new byte[4];
		long Eposition = 0;
		try {
			mRaf.seek(0);
			mPosition = 0;
			mRaf.read(flag);
			if (!new String(flag).equals("SM4:")) {
				mRaf.seek(position);
				mPosition = (int)position;
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
					mPosition += (int)position;
					Eposition += position;
					mRaf.seek(mRaf.getFilePointer() - 4);
					return Eposition;
				} else {
					mPosition += len;
					Eposition += tmplen;
					mRaf.skipBytes(tmplen);
				}
				position -= len;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return Eposition;
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
	
	private long D2EPosition(long position) {
		long Eposition = 0;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(mFile, "r");
			byte[] flag = new byte[4];
			raf.read(flag);
			if (!new String(flag).equals("SM4:")) {
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
		} catch (Exception e) {
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
	
	public FileChannel getChannel() {
		FileChannel fileChannel = mRaf.getChannel();
		mFcm = new FileChannelMode(fileChannel);
		return fileChannel;
	}

	class FileChannelMode implements BaseChannelMode {

		private FileChannel mFileChannel;
		private FileChannel mRafFileChannel;
		private long mPositionChannel;

		public FileChannelMode(FileChannel fileChannel) {
			mRafFileChannel = mRaf.getChannel();
			mPositionChannel = mPosition; 
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
			return mPositionChannel;
		}

		public FileChannel position(long offset) throws IOException {
			System.out.println("--------------position----------------");
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
				mCurrentStartPosition = tmplen - (int)(mRaf.getFilePointer() - Eposition);
			}
			mAvilibale = (int)length() - mPosition;
			return mRafFileChannel.position(Eposition);
		}
		//读取会影响到依赖的流
		public int read(ByteBuffer buffer) throws IOException {
			System.out.println("--------------read----------------");
			int needLen = buffer.limit();
			byte[] readBytes = new byte[needLen];
			int byteOffset = 0;
			if (available() == 0) {
				return -1;//明文读取在上一次已读完
			}
			int length = mCurrentDecryptBytes.length - mCurrentStartPosition;// 可用明文长度
			if (length >= needLen) {
				System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, readBytes, byteOffset, needLen);
				mCurrentStartPosition += needLen;
				mAvilibale -= needLen;
				mPosition += needLen;
				buffer.put(readBytes);
				return needLen;//当前明文满足本次读取
			} else {
				mRaf.seek(mStartPosition);
				System.arraycopy(mCurrentDecryptBytes, mCurrentStartPosition, readBytes, byteOffset, length);
				mAvilibale -= length;
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
							mAvilibale -= len;
							mPosition += len;
						} else {// 可用明文长度已满足需要
							mCurrentStartPosition = needLen - length + len;// 最新明文段需要被读取长度
							System.arraycopy(Dcontent, 0, readBytes, byteOffset, mCurrentStartPosition);
							mCurrentDecryptBytes = new byte[len];
							System.arraycopy(Dcontent, 0, mCurrentDecryptBytes, 0, len);
							mAvilibale -= mCurrentStartPosition;
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
		//读取不影响到依赖的流
		public int read(ByteBuffer buffer, long position) throws IOException {
			System.out.println("---------------------read----------------------");
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
		public int write(ByteBuffer src) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int write(ByteBuffer buffer, long position) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long write(ByteBuffer[] buffers) throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long write(ByteBuffer[] buffers, int offset, int length)
				throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}
	}
	
	public FileStreamDecryptMode(File file) {
		this.mFile = file;
		try {
//			mFileDecryptStream = new FileInputStream(file);
			mRaf = new RandomAccessFile(file, "r");
			checkEncrypt();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public FileStreamDecryptMode(String path) {
		this.mPath = path;
		try {
//			mFileDecryptStream = new FileInputStream(path);
			mRaf = new RandomAccessFile(path, "r");
			mFile = new File(path);
			checkEncrypt();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public FileStreamDecryptMode(FileDescriptor fd) {
		this.mFd = fd;
		try {
//			mFileDecryptStream = new FileInputStream(fd);
			checkEncrypt();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public BaseChannelMode getFileChannelMode() {
		return mFcm;
	}

}
