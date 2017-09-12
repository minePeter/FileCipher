package com.dema.cipher.wrapper;

import java.io.UnsupportedEncodingException;
import java.util.Set;


public class SharedPreferencesMode {
	
	public static String EncryptString(String DString) throws UnsupportedEncodingException {
		byte[] Dbytes = DString.getBytes();
		int len = Dbytes.length;
		int tmplen = FileUtil.D2Elength(len);
		byte[] head = TypeConverHelper.intToBytes(len);
		byte[] DContent = new byte[tmplen];
		byte[] EContent = new byte[tmplen];
		System.arraycopy(Dbytes, 0, DContent, 0, len);
		SMS4.getSMS4Instance().sms4(DContent, tmplen, SMS4.key, EContent, SMS4.ENCRYPT);
		return new String(head, "ISO-8859-1") + new String(EContent, "ISO-8859-1");
	}
	
	public static String DecryptString(String EString) throws Exception{
		byte[] Ebytes = EString.getBytes("ISO-8859-1");
		byte[] head = new byte[4];
		System.arraycopy(Ebytes, 0, head, 0, 4);
		int len = TypeConverHelper.bytesToInt(head);
		int tmplen = FileUtil.D2Elength(len);
		byte[] DContent = new byte[tmplen];
		byte[] EContent = new byte[tmplen];
		System.arraycopy(Ebytes, 4, EContent, 0, tmplen);
		SMS4.getSMS4Instance().sms4(EContent, tmplen, SMS4.key, DContent, SMS4.DECRYPT);
		byte[] Dbytes = new byte[len];
		System.arraycopy(DContent, 0, Dbytes, 0, len);
		return new String(Dbytes);
	}
	
	public static Set<String> EncryptStringSet(Set<String> StringSet) throws UnsupportedEncodingException {
		String[] strs= new String[StringSet.size()];
		int index = 0;
		for (String str : StringSet) {
			strs[index++] = EncryptString(str);
		}
		StringSet.clear();
		for (String str : strs) {
			StringSet.add(str);
		}
		return StringSet;
	}
	
	public static Set<String> DecryptStringSet(Set<String> StringSet) throws Exception{
		String[] strs= new String[StringSet.size()];
		int index = 0;
		for (String str : StringSet) {
			strs[index++] = DecryptString(str);
		}
		StringSet.clear();
		for (String str : strs) {
			StringSet.add(str);
		}
		return StringSet;
	}
	
	public static String EncryptInt(int Dint) throws UnsupportedEncodingException {
		byte[] Dbytes = TypeConverHelper.intToBytes(Dint);
		byte[] DContent = new byte[16];
		byte[] EContent = new byte[16];
		System.arraycopy(Dbytes, 0, DContent, 0, 4);
		SMS4.getSMS4Instance().sms4(DContent, 16, SMS4.key, EContent, SMS4.ENCRYPT);
		return new String(EContent, "ISO-8859-1");
	}
	
	public static int DecryptInt(String EString) throws Exception{
		byte[] EContent = EString.getBytes("ISO-8859-1");
		byte[] DContent = new byte[16];
		SMS4.getSMS4Instance().sms4(EContent, 16, SMS4.key, DContent, SMS4.DECRYPT);
		byte[] Dbytes = new byte[4];
		System.arraycopy(DContent, 0, Dbytes, 0, 4);
		return TypeConverHelper.bytesToInt(Dbytes);
	}
	
	public static String EncryptFloat(float DFlat) throws UnsupportedEncodingException {
		byte[] Dbytes = TypeConverHelper.floatToBytes(DFlat);
		byte[] DContent = new byte[16];
		byte[] EContent = new byte[16];
		System.arraycopy(Dbytes, 0, DContent, 0, 4);
		SMS4.getSMS4Instance().sms4(DContent, 16, SMS4.key, EContent, SMS4.ENCRYPT);
		return new String(EContent, "ISO-8859-1");
	}
	
	public static float DecryptFloat(String EString) throws Exception{
		byte[] EContent = EString.getBytes("ISO-8859-1");
		byte[] DContent = new byte[16];
		SMS4.getSMS4Instance().sms4(EContent, 16, SMS4.key, DContent, SMS4.DECRYPT);
		byte[] Dbytes = new byte[4];
		System.arraycopy(DContent, 0, Dbytes, 0, 4);
		return TypeConverHelper.bytesToFloat(Dbytes);
	}
	
	public static String EncryptDouble(double DDouble) throws UnsupportedEncodingException {
		byte[] Dbytes = TypeConverHelper.doubleToBytes(DDouble);
		byte[] DContent = new byte[16];
		byte[] EContent = new byte[16];
		System.arraycopy(Dbytes, 0, DContent, 0, 8);
		SMS4.getSMS4Instance().sms4(DContent, 16, SMS4.key, EContent, SMS4.ENCRYPT);
		return new String(EContent, "ISO-8859-1");
	}
	
	public static double DecryptDouble(String EString) throws Exception{
		byte[] EContent = EString.getBytes("ISO-8859-1");
		byte[] DContent = new byte[16];
		SMS4.getSMS4Instance().sms4(EContent, 16, SMS4.key, DContent, SMS4.DECRYPT);
		byte[] Dbytes = new byte[4];
		System.arraycopy(DContent, 0, Dbytes, 0, 8);
		return TypeConverHelper.bytesToDouble(Dbytes);
	}
	
	public static String EncryptLong(long DLong) throws UnsupportedEncodingException {
		byte[] Dbytes = TypeConverHelper.longToBytes(DLong);
		byte[] DContent = new byte[16];
		byte[] EContent = new byte[16];
		System.arraycopy(Dbytes, 0, DContent, 0, 8);
		SMS4.getSMS4Instance().sms4(DContent, 16, SMS4.key, EContent, SMS4.ENCRYPT);
		return new String(EContent, "ISO-8859-1");
	}
	
	public static long DecryptLong(String EString) throws Exception{
		byte[] EContent = EString.getBytes("ISO-8859-1");
		byte[] DContent = new byte[16];
		SMS4.getSMS4Instance().sms4(EContent, 16, SMS4.key, DContent, SMS4.DECRYPT);
		byte[] Dbytes = new byte[4];
		System.arraycopy(DContent, 0, Dbytes, 0, 8);
		return TypeConverHelper.bytesToLong(Dbytes);
	}
}
