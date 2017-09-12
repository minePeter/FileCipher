package com.dema.cipher;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.dema.cipher.utils.IOUtilsMode;
import com.dema.cipher.wrapper.RandomAccessFileMode;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class MainActivity extends Activity {

    EditText edit;
    final static String fileName = Environment.getExternalStorageDirectory().getAbsolutePath() + "/log.txt";
    int count = 0;

    @SuppressLint("NewApi")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        edit = (EditText)findViewById(R.id.inputEditText);
    }


    public void input(View v) {
        try {
            File file = new File(fileName);
            if(file.exists()) {
                file.delete();
            }
            if(!file.exists()) {
                file.createNewFile();
            }

            String input = edit.getText().toString();
            count = input.getBytes().length;
            ///////////////////////////////////////////////////////
//            FileStreamEncryptMode fileStreamEncryptMode = new FileStreamEncryptMode(file, true);
//            fileStreamEncryptMode.write(input.getBytes());
//            fileStreamEncryptMode.close();
            ///////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////
//            RandomAccessFileMode randomAccessFileMode = new RandomAccessFileMode(file, "rw");
//            randomAccessFileMode.write(input.getBytes());
//            randomAccessFileMode.write(input.getBytes());
//            randomAccessFileMode.close();
            ///////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////
            RandomAccessFileMode randomAccessFileMode = new RandomAccessFileMode(file, "rw");
            randomAccessFileMode.getChannel();
            RandomAccessFileMode.FileChannelMode fileChannelMode = randomAccessFileMode.getFileChannelMode();
            ByteBuffer buffer = ByteBuffer.wrap(input.getBytes());
            fileChannelMode.write(buffer);
            randomAccessFileMode.close();
            ///////////////////////////////////////////////////////

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void output(View v) {
        try {
            File file = new File(fileName);
            if(!file.exists()) {
                return;
            }
//            byte[] bytes = new byte[count *  2];
            ///////////////////////////////////////////////////////
//            FileStreamDecryptMode fileStreamDecryptMode = new FileStreamDecryptMode(file);
//            fileStreamDecryptMode.read(bytes);
//            fileStreamDecryptMode.close();
            ///////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////
//            RandomAccessFileMode randomAccessFileMode = new RandomAccessFileMode(file, "rw");
//            randomAccessFileMode.read(bytes);
//            randomAccessFileMode.close();
            ///////////////////////////////////////////////////////
//            String str = new String(bytes);
//            Toast.makeText(this, str, Toast.LENGTH_LONG).show();
//            System.out.println("output:"+str);

            ///////////////////////////////////////////////////////
            RandomAccessFileMode randomAccessFileMode = new RandomAccessFileMode(file, "rw");
            randomAccessFileMode.getChannel();
            RandomAccessFileMode.FileChannelMode fileChannelMode = randomAccessFileMode.getFileChannelMode();
            ByteBuffer buffer = ByteBuffer.allocate(count);
            fileChannelMode.read(buffer);
            ///////////////////////////////////////////////////////
            String str = IOUtilsMode.byteBufferToString(buffer);
            Toast.makeText(this, str, Toast.LENGTH_LONG).show();
            System.out.println("output:"+str);
            randomAccessFileMode.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
