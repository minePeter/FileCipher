package com.dema.cipher.wrapper;
/**
 * 类名: AndroidHelper <br/> 
 * 功能: android 帮助类. <br/> 
 * @since Jdk 1.6
 */
public class AndroidHelper {

	/**
	 * getMIMEType:根据文件名后缀判断文件类型. <br/> 
	 * @param fileName
	 * @return
	 */
	public static String getMIMEType(String fileName) {
		String type = "";
		String fName = fileName;
		/* 取得扩展名 */
		String end = fName.substring(fName.lastIndexOf(".") + 1, fName.length()).toLowerCase();

		/* 依扩展名的类型决定MimeType */
		if (end.equals("m4a") || end.equals("mp3") || end.equals("mid")
				|| end.equals("xmf") || end.equals("ogg") || end.equals("wav")) {
			type = "audio/*";
		} else if (end.equals("3gp") || end.equals("mp4")) {
			type = "video/*";
		} else if (end.equals("txt")) {
			type = "text/plain";
		} else if (end.equals("jpg") || end.equals("gif") || end.equals("png")
				|| end.equals("jpeg") || end.equals("bmp")) {
			type = "image/*";
		} else if (end.equals("apk")) {
			type = "application/vnd.android.package-archive";
		} else if (end.equals("doc") || end.equals("docx")) {
			type = "application/msword";
		} else if (end.equals("xls") || end.equals("xlsx") || end.equals("csv")) {
			type = "application/vnd.ms-excel";
		} else if (end.equals("pdf")) {
			type = "application/pdf";
		} else if (end.equals("chm")) {
			type = "application/x-chm";
		} else if (end.equals("ppt") || end.equals("pptx")) {
			type = "application/vnd.ms-powerpoint";
		} else if (end.equals("wps") || end.equals("dps") || end.equals("et")) {
			type = "application/vnd.ms-works";
		} else {
			type = "/*";
		}
		return type;
	}

}
