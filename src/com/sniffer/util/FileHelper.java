package com.sniffer.util;
import org.pcap4j.core.PcapPacket;
import java.io.*;


/**
 * 使用此类来包装所有与文件操作有关的函数
 * @author wxy
 * @version 1.0
 */


public class FileHelper {

    /**
     * 添加一行报文到文件中
     * 如果文件不存在 则创建新文件
     *
     * @param filePath 文件名
     * @param packet   数据对象
     * @throws IOException
     * @since 1.8+
     */
    public static void appendLine(String filePath, PcapPacket packet) throws IOException {
        File file = new File(filePath);
        PrintWriter pw = null;
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(filePath, true);
        pw = new PrintWriter(fos);
        String newLine = packet.getTimestamp().toString();
        pw.println(newLine);
        pw.flush();
        newLine = packet.getPacket().toString();
        pw.println(newLine);
        pw.flush();
        pw.close();
    }

}


