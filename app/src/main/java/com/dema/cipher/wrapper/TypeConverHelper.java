package com.dema.cipher.wrapper;


public class TypeConverHelper {

	/**
	 * 将int数值转换为占四个字节的byte数组，本方法适用于(高位在前，低位在后)的顺序。 和bytesToInt（）配套使用
	 */
	public static byte[] intToBytes(int value) {
		byte[] src = new byte[4];
		src[0] = (byte) ((value >> 24) & 0xFF);
		src[1] = (byte) ((value >> 16) & 0xFF);
		src[2] = (byte) ((value >> 8) & 0xFF);
		src[3] = (byte) (value & 0xFF);
		return src;
	}

	/**
	 * byte数组中取int数值，本方法适用于(低位在后，高位在前)的顺序。和intToBytes（）配套使用
	 */
	public static int bytesToInt(byte[] src) {
		int value;
		value = (int) (((src[0] & 0xFF) << 24) | ((src[1] & 0xFF) << 16)
				| ((src[2] & 0xFF) << 8) | (src[3] & 0xFF));
		return value;
	}
	
    //字符到字节转换  
    public static byte[] charToBytes(char ch){  
      int temp=(int)ch;  
      byte[] b=new byte[2];  
      for (int i=b.length-1;i>-1;i--){  
        b[i] = new Integer(temp & 0xff).byteValue();      //将最高位保存在最低位  
        temp = temp >> 8;       //向右移8位  
      }  
      return b;  
    }  
    
    //字节到字符转换  
    
    public static char bytesToChar(byte[] b){  
      int s=0;  
      if(b[0]>0)  
        s+=b[0];  
      else  
        s+=256+b[0];  
      s*=256;  
      if(b[1]>0)  
        s+=b[1];  
      else  
        s+=256+b[1];  
      char ch=(char)s;  
      return ch;  
    }  
    
    //浮点到字节转换  
    public static byte[] doubleToBytes(double d){  
      byte[] b=new byte[8];  
      long l=Double.doubleToLongBits(d);  
      for(int i=0;i<b.length;i++){  
        b[i]=new Long(l).byteValue();  
        l=l>>8;  
    
      }  
      return b;  
    }  
    
    //字节到浮点转换  
    public static double bytesToDouble(byte[] b){  
      long l;  
    
      l=b[0];  
      l&=0xff;  
      l|=((long)b[1]<<8);  
      l&=0xffff;  
      l|=((long)b[2]<<16);  
      l&=0xffffff;  
      l|=((long)b[3]<<24);  
      l&=0xffffffffl;  
      l|=((long)b[4]<<32);  
      l&=0xffffffffffl;  
    
      l|=((long)b[5]<<40);  
      l&=0xffffffffffffl;  
      l|=((long)b[6]<<48);  
    
      l|=((long)b[7]<<56);  
      return Double.longBitsToDouble(l);  
    } 
    
    /** 
     * 浮点转换为字节 
     *  
     * @param f 
     * @return 
     */  
    public static byte[] floatToBytes(float f) {  
          
        // 把float转换为byte[]  
        int fbit = Float.floatToIntBits(f);  
          
        byte[] b = new byte[4];    
        for (int i = 0; i < 4; i++) {    
            b[i] = (byte) (fbit >> (24 - i * 8));    
        }   
        // 翻转数组  
        int len = b.length;  
        // 建立一个与源数组元素类型相同的数组  
        byte[] dest = new byte[len];  
        // 为了防止修改源数组，将源数组拷贝一份副本  
        System.arraycopy(b, 0, dest, 0, len);  
        byte temp;  
        // 将顺位第i个与倒数第i个交换  
        for (int i = 0; i < len / 2; ++i) {  
            temp = dest[i];  
            dest[i] = dest[len - i - 1];  
            dest[len - i - 1] = temp;  
        }  
        return dest;  
    }  
      
    /** 
     * 字节转换为浮点 
     *  
     * @param b 字节（至少4个字节） 
     * @return
     */  
    public static float bytesToFloat(byte[] b) {    
        int l;                                             
        l = b[0];                                  
        l &= 0xff;                                         
        l |= ((long) b[1] << 8);                   
        l &= 0xffff;                                       
        l |= ((long) b[2] << 16);                  
        l &= 0xffffff;                                     
        l |= ((long) b[3] << 24);                  
        return Float.intBitsToFloat(l);                    
    }
    
	// long类型转成byte数组
	public static byte[] longToBytes(long number) {
		long temp = number;
		byte[] b = new byte[8];
		for (int i = 0; i < b.length; i++) {
			b[i] = new Long(temp & 0xff).byteValue();// 将最低位保存在最低位
			temp = temp >> 8; // 向右移8位
		}
		return b;
	}

	// byte数组转成long
	public static long bytesToLong(byte[] b) {
		long s = 0;
		long s0 = b[0] & 0xff;// 最低位
		long s1 = b[1] & 0xff;
		long s2 = b[2] & 0xff;
		long s3 = b[3] & 0xff;
		long s4 = b[4] & 0xff;// 最低位
		long s5 = b[5] & 0xff;
		long s6 = b[6] & 0xff;
		long s7 = b[7] & 0xff;

		// s0不变
		s1 <<= 8;
		s2 <<= 16;
		s3 <<= 24;
		s4 <<= 8 * 4;
		s5 <<= 8 * 5;
		s6 <<= 8 * 6;
		s7 <<= 8 * 7;
		s = s0 | s1 | s2 | s3 | s4 | s5 | s6 | s7;
		return s;
	}
}
