package com.dema.cipher.wrapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;


public interface BaseChannelMode {
	
	public int write(ByteBuffer src) throws IOException;

	public int write(ByteBuffer buffer, long position) throws IOException;

	public long write(ByteBuffer[] buffers) throws IOException;

	public long write(ByteBuffer[] buffers, int offset, int length) throws IOException;
	
	public FileLock lock() throws IOException;

	public FileLock lock(long position, long size, boolean shared) throws IOException;

	public MappedByteBuffer map(FileChannel.MapMode mode, long position, long size) throws IOException;

	public long position() throws IOException;

	public FileChannel position(long offset) throws IOException;

	public int read(ByteBuffer buffer) throws IOException;

	public int read(ByteBuffer buffer, long position) throws IOException;

	public long read(ByteBuffer[] buffers) throws IOException;

	public long read(ByteBuffer[] buffers, int start, int number) throws IOException;

	public long size() throws IOException;

	public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException;

	public long transferTo(long position, long count, WritableByteChannel target) throws IOException;

	public FileChannel truncate(long size) throws IOException;
}
