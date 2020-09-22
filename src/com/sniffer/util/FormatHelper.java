package com.sniffer.util;


import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * 使用此类来包装所有与格式检查与转换的操作
 * @author wxy
 * @version 1.6
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
        return (check>=0&&check<=10000);
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

    public static boolean checkIpAddress(String ip){
        boolean isIPv4 = true;
        if(ip.equals("")){
            return true;
        }

        try {
            final InetAddress inet = Inet4Address.getByName(ip);
        } catch (final UnknownHostException e) {
            isIPv4 = false;
        }
        return isIPv4;
    }

    public static boolean checkPort(String port){
        boolean isPort = true;
        if(port.equals(""))
            return true;
        try {
            int temp =Integer.parseInt(port);
            if(temp<0 || temp>65535)
                isPort = false;
        }catch (Exception e){
            isPort = false;
        }
        return isPort;
    }


    public static String detailInformationFormat(PcapPacket packet){
        String build = "";
        String split = "        ";
        build = build +"探测时间:" + packet.getTimestamp().atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm:ss:SSSSS")) +"\n";
        build = build + "报文总长:" + packet.length() + "\n";
        EthernetPacket ePacket = packet.getPacket().get(EthernetPacket.class);
        build = build + "-----以太网帧(Frame)-----\n";
        build = build + "下层协议类型:" + ePacket.getHeader().getType() + split;
        build = build + "头部长度:" + ePacket.getHeader().length()+"\n";
        build = build + "源MAC地址:" + ePacket.getHeader().getSrcAddr()+"\n";
        build = build + "目的MAC地址:" + ePacket.getHeader().getDstAddr()+"\r\n";

        if(ePacket.getHeader().getType() == EtherType.IPV4){
            IpV4Packet i4Packet = ePacket.get(IpV4Packet.class);
            build = build + "-----IPV4数据报(Datagram)-----\n";

            build = build + "下层协议类型:" + i4Packet.getHeader().getProtocol().name() + "\n";
            build = build + "源IP地址:" + i4Packet.getHeader().getSrcAddr() + "\n";
            build = build + "目的IP地址:" + i4Packet.getHeader().getDstAddr() + "\n";
            build = build + "TTL:" + Integer.toString(i4Packet.getHeader().getTtlAsInt()) + split;
            build = build + "标识:" + Integer.toString(i4Packet.getHeader().getIdentificationAsInt()) + "\r\n";
            if(i4Packet.getHeader().getProtocol() == IpNumber.TCP){
                build = build + "-----TCP报文段(Segment)-----\n";
                TcpPacket tPacket = i4Packet.get(TcpPacket.class);
                build = build + "源端口:" + tPacket.getHeader().getSrcPort() + "\n";
                build = build + "目的端口" + tPacket.getHeader().getDstPort() + "\n";
                build = build + "序列号:" + Integer.toString(tPacket.getHeader().getSequenceNumber()) + split;
                build = build + "确认号:" + Integer.toString(tPacket.getHeader().getAcknowledgmentNumber()) + "\n";
                build = build + "URG:ACK:PSH:RST:SYN:FIN = " + boolFormat(tPacket.getHeader().getUrg(),tPacket.getHeader().getAck(),
                        tPacket.getHeader().getPsh(),tPacket.getHeader().getRst(),tPacket.getHeader().getSyn(),
                        tPacket.getHeader().getFin()) + "\n";
                build = build + "应用层负载:" + tPacket.getPayload()+ "\n";
            } else if(i4Packet.getHeader().getProtocol() == IpNumber.UDP){
                build = build + "-----UDP报文段(Segment)-----\n";
                UdpPacket uPacket = i4Packet.get(UdpPacket.class);
                build = build + "源端口:" + uPacket.getHeader().getSrcPort() + "\n";
                build = build + "目的端口:" + uPacket.getHeader().getDstPort() + "\n";
                build = build + "应用层负载:" + uPacket.getPayload()+ "\n";
            } else if(i4Packet.getHeader().getProtocol() == IpNumber.IGMP){
                build = build + "-----IGMP报文段(Segment)-----\n";
                build = build + "IGMP配置:" + i4Packet.getHeader().getOptions() + "\n";
                build = build + "报文负载:" + i4Packet.getPayload() + "\n";
            } else if(i4Packet.getHeader().getProtocol() == IpNumber.ICMPV4){
                build = build + "-----ICMPv4报文段(Segment)-----\n";
                build = build + "报文负载:" + i4Packet.getPayload() + "\n";
            } else{
                build = build + "-----其他报文段(Segment)-----\n";
                build = build + "报文负载:" + i4Packet.getPayload() + "\n";
            }
        }

        if(ePacket.getHeader().getType() == EtherType.IPV6){
            IpV6Packet i6Packet = ePacket.get(IpV6Packet.class);
            build = build + "-----IPV6数据报(Datagram)-----\n";

            build = build + "源地址:" + i6Packet.getHeader().getSrcAddr() + "\n";
            build = build + "目的地址:" + i6Packet.getHeader().getDstAddr() + "\n";
            build = build + "底层协议:" + i6Packet.getHeader().getProtocol().name() + "\n";
            build = build + "报文负载:" + i6Packet.getPayload() + "\n";

        }

        if(ePacket.getHeader().getType() == EtherType.ARP){
            ArpPacket aPacket = ePacket.get(ArpPacket.class);
            build = build + "-----ARP数据报(Datagram)-----\n";
            build = build + "硬件类型:" + aPacket.getHeader().getHardwareType() + "\n";
            build = build + "操作类型:" + aPacket.getHeader().getOperation()+ "\n";
            build = build + "源硬件MAC地址:" + aPacket.getHeader().getSrcHardwareAddr()+ "\n";
            build = build + "源协议地址:" + aPacket.getHeader().getSrcProtocolAddr()+ "\n";
            build = build + "目的硬件MAC地址:" + aPacket.getHeader().getDstHardwareAddr()+ "\n";
            build = build + "目的协议地址:" + aPacket.getHeader().getDstProtocolAddr()+ "\n";
        }

        return build;
    }

    private static String boolFormat(boolean a,boolean b,boolean c,boolean d,boolean e,boolean f){
        String build = "";
        if(a){
            build = build + "1:";
        }else {
            build = build + "0:";
        }
        if(b){
            build = build + "1:";
        }else {
            build = build + "0:";
        }
        if(c){
            build = build + "1:";
        }else {
            build = build + "0:";
        }
        if(d){
            build = build + "1:";
        }else {
            build = build + "0:";
        }
        if(e){
            build = build + "1:";
        }else {
            build = build + "0:";
        }
        if(f){
            build = build + "1";
        }else {
            build = build + "0";
        }
        return build;
    }


}
