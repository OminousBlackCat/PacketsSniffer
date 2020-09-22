package com.sniffer.util;


import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 使用此类来包装所有与文件路径获取有关的函数
 * @author wxy
 * @version 1.0
 * @since 1.7+
 */
public class FilePathHelper {

    public static String FILE_PATH = null;
    public static String CONFIG_PATH = System.getProperty("user.dir")+ File.separator+"config";
    public static String PACKETSAVE_PATH;

    public static void createSavePath()throws IOException {
        if(FILE_PATH != null){
            return;
        }
        String dateString = new SimpleDateFormat("MM-dd_hh-mm-ss").format(new Date());
        FILE_PATH = System.getProperty("user.dir")+File.separator+"save"+File.separator + dateString;
        Path dirPath = Paths.get(FILE_PATH);
        if(!Files.exists(dirPath)){
            Files.createDirectories(dirPath);
        }
        PACKETSAVE_PATH = FILE_PATH;
    }

}
