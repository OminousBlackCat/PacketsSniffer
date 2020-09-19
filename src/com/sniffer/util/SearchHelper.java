package com.sniffer.util;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import java.net.UnknownHostException;

/**
 * 使用此类搜索过滤相关操作
 * @author wxy
 * @version 1.1
 */
public class SearchHelper {

    public static String etherProtocol;
    public static String downProtocol;
    public static String srcIp;
    public static String dstIp;
    public static String allIp;
    public static String srcPort;
    public static String dstPort;

    public static boolean searchPacket(PcapPacket packet) throws UnknownHostException {
        boolean firstCondition = false;
        if (etherProtocol.equals("---"))
            firstCondition = true;
        if(etherProtocol.equals("ARP")){
            if(packet.get(ArpPacket.class) != null)
                firstCondition =true;
        }

        if(etherProtocol.equals("IPv4")){
            if(packet.get(IpV4Packet.class) != null)
                firstCondition = true;
        }

        if(etherProtocol.equals("IPv6")){
            if(packet.get(IpV6Packet.class) != null)
                firstCondition =true;
        }

        if(!firstCondition)
            return false;

        boolean secondCondition = false;
        if(downProtocol.equals("---")){
            secondCondition = true;
        }
        if(downProtocol.equals("TCP")){
            if(packet.get(TcpPacket.class) != null)
                secondCondition = true;
        }
        if(downProtocol.equals("UDP")){
            if(packet.get(UdpPacket.class) != null)
                secondCondition = true;
        }
        if(downProtocol.equals("DNS")){
            if(packet.get(DnsPacket.class) != null)
                secondCondition = true;
        }
        if(downProtocol.equals("IGMP")){
            IpV4Packet temp4 = packet.get(IpV4Packet.class);
            IpV6Packet temp6 = packet.get(IpV6Packet.class);
            if(temp4 != null){
                if(temp4.getHeader().getProtocol() == IpNumber.IGMP)
                    secondCondition = true;
            }
            if(temp6 != null){
                if(temp6.getHeader().getProtocol() == IpNumber.IGMP)
                    secondCondition = true;
            }
        }
        if(downProtocol.equals("ICMP")){
            IpV4Packet temp4 = packet.get(IpV4Packet.class);
            IpV6Packet temp6 = packet.get(IpV6Packet.class);
            if(temp4 != null){
                if(temp4.getHeader().getProtocol() == IpNumber.ICMPV4)
                    secondCondition = true;
            }
            if(temp6 != null){
                if(temp6.getHeader().getProtocol() == IpNumber.ICMPV6)
                    secondCondition = true;
            }
        }

        if(downProtocol.equals("IPV6_HOPOPT")){
            IpV6Packet temp6 = packet.get(IpV6Packet.class);
            if(temp6 != null){
                if(temp6.getHeader().getProtocol() == IpNumber.IPV6_HOPOPT)
                    secondCondition = true;
            }
        }
        if(downProtocol.equals("HTTP(S)")){
            TcpPacket temp = packet.get(TcpPacket.class);
            if(temp != null){
                if(temp.getHeader().getDstPort() == TcpPort.HTTPS ||
                        temp.getHeader().getSrcPort() == TcpPort.HTTPS ||
                        temp.getHeader().getDstPort() == TcpPort.HTTP ||
                        temp.getHeader().getSrcPort() == TcpPort.HTTP)
                    secondCondition = true;
            }
        }
        if(!secondCondition)
            return false;


        if(!srcIp.equals("")){
            IpV4Packet temp = packet.get(IpV4Packet.class);
            if(temp != null){
                if(!temp.getHeader().getSrcAddr().getHostAddress().equals(srcIp))
                    return false;
            }else
                return false;
        }

        if(!dstIp.equals("")){
            IpV4Packet temp = packet.get(IpV4Packet.class);
            if(temp != null){
                if(!temp.getHeader().getDstAddr().getHostAddress().equals(dstIp))
                    return false;
            }else
                return false;
        }

        if(!allIp.equals("")){
            IpV4Packet temp = packet.get(IpV4Packet.class);
            if(temp != null){
                if(!temp.getHeader().getDstAddr().getHostAddress().equals(allIp) &&
                !temp.getHeader().getSrcAddr().getHostAddress().equals(allIp))
                    return false;
            }else
                return false;

        }


        if(!srcPort.equals("")){
            TcpPacket tTemp = packet.get(TcpPacket.class);
            UdpPacket uTemp = packet.get(UdpPacket.class);
            if(tTemp == null && uTemp == null)
                return false;
            if(tTemp != null){
                if(!tTemp.getHeader().getSrcPort().valueAsString().equals(srcPort))
                    return false;
            }
            if(uTemp != null){
                if (!uTemp.getHeader().getSrcPort().valueAsString().equals(srcPort))
                    return false;
            }
        }

        if(!dstPort.equals("")){
            TcpPacket tTemp = packet.get(TcpPacket.class);
            UdpPacket uTemp = packet.get(UdpPacket.class);
            if(tTemp == null && uTemp == null)
                return false;
            if(tTemp != null){
                if(!tTemp.getHeader().getDstPort().toString().equals(dstPort))
                    return false;
            }
            if(uTemp != null){
                if (!uTemp.getHeader().getDstPort().toString().equals(dstPort))
                    return false;
            }
        }


        return true;
    }



}
