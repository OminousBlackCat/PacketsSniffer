package com.sniffer.util;


import org.pcap4j.core.PcapPacket;

/**
 * 使用此类来包装所有与格式检查与转换的操作
 * @author wxy
 * @version 1.0
 */
public class FormatHelper {


    public static String getNICName(String originName){
        String name;
        switch (originName.substring(0,3)){
            case "eth":
                name =  "以太网"+originName.substring(3);
                break;
            case "wla":
                name =  "无线网适配器"+originName.substring(4);
                break;
                default:
                    name = originName;

        }
        return name;
    }

    public static boolean checkSnapLength(String length){
        int check;
        try {
            check = Integer.parseInt(length);
        }catch (Exception e){
            return false;
        }

        return (check>0&&check<=65536);
    }

    public static boolean checkSnapTimeout(String timeout){
        int check;
        try {
            check = Integer.parseInt(timeout);
        }catch (Exception e){
            return false;
        }
        return (check>=10&&check<=10000);
    }

    public static boolean isIpv4Packet(PcapPacket packet){
        String temp = packet.getPacket().getPayload().getHeader().toString();
        String[] parseHeader = temp.split("\r\n");
        System.out.println(parseHeader[0]);
        String[] parseVersion = parseHeader[0].split(" ");
        if(parseVersion[0].equals("[IPv6"))
            return false;
        return true;
    }

}
