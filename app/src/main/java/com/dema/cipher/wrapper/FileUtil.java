package com.dema.cipher.wrapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import android.os.Environment;

public class FileUtil {
	
	private static String mFloder = Environment.getExternalStorageDirectory() + "/tsSecFile";
	static {
		File path = new File(mFloder);
		if(!path.exists()) {
			try {
				path.mkdirs();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * 补位（SM4算法要求加密长度为16的整数倍）
	 * 
	 * @param len
	 *            明文实际长度
	 * @return 密文长度
	 */
	public static int D2Elength(int len) {
		int tmplen = len;
		if (len % 16 != 0) {
			tmplen = (len / 16 + 1) * 16;
		}
		return tmplen;
	}
	
	/**
	 * 解密文件
	 * 
	 * @param len
	 *            明文实际长度
	 * @return 密文长度
	 * @throws IOException 
	 */
	public static File D2EFile(File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		byte[] flag = new byte[4];
		byte[] head = new byte[4];
		
		if(fis.read(flag)==4) {
			String flagStr = new String(flag);
			if(!flagStr.equals("SM4:")) {
				fis.close();
				return file;
			}
		} else {
			fis.close();
			return file;
		}
		File parentPath = new File(mFloder + "/" + file.getParent().toString());
		if(!parentPath.exists()) {
			parentPath.mkdirs();
		}
		String filepath =  mFloder + file.getAbsolutePath();
		//解密到Cache目录下，需要第三方程序能够访问本程序
//		String filepath =  context.getCacheDir() + "/" + file.getName();
		File newFile = new File(filepath);
		if(newFile.exists()) {
			newFile.delete();
		}
		newFile.createNewFile();
		FileOutputStream fos = new FileOutputStream(newFile);
		while(fis.read(head)==4) {
			int len = TypeConverHelper.bytesToInt(head);
			int tmplen = FileUtil.D2Elength(len);
			byte[] Econtent = new byte[tmplen];
			byte[] Dcontent = new byte[tmplen];
			if(fis.read(Econtent)!=-1) {
				SMS4.getSMS4Instance().sms4(Econtent, tmplen, SMS4.key, Dcontent, SMS4.DECRYPT);
				fos.write(Dcontent, 0, len);
			} else {
				fis.close();
				fos.close();
				newFile.delete();
				return file;
			}
		}
		fis.close();
		fos.close();
		return newFile;
	}
}
