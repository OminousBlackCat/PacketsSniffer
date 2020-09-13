package com.sniffer.net;

import com.sniffer.util.FileHelper;
import com.sniffer.util.FilePathHelper;
import com.sniffer.util.FormatHelper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.Properties;
import static java.lang.Thread.dumpStack;
import static java.lang.Thread.sleep;

public class SnifferTest {

    public static void main(String args[]){

        try {
            InetAddress addr = InetAddress.getByName("10.203.156.33");
            PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
            int timeout = 10;
            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            FilePathHelper.createSavePath();
            while (true){
                //System.out.println(handle.getNextPacket());
                PcapPacket temp = handle.getNextPacket();
                if(temp != null){
                    //System.out.println(temp.getPacket());
                    FileHelper.appendLine(FilePathHelper.PACKETSAVE_PATH + File.separator + "1.txt",temp);
                    System.out.println(FormatHelper.isIpv4Packet(temp));

                    Properties properties = new Properties();
                    properties.load(new ByteArrayInputStream(temp.getPacket().getPayload().getHeader().toString().getBytes()));
                    System.out.println(properties.getProperty("Protocol"));
                }
                sleep(1000);
            }
//            Enumeration<NetworkInterface> netInterfaces;
//            netInterfaces = NetworkInterface.getNetworkInterfaces();
//            while (netInterfaces.hasMoreElements()) {
//                NetworkInterface ni = netInterfaces.nextElement();
//                Enumeration<InetAddress> addresses = ni.getInetAddresses();
//                while (addresses.hasMoreElements()) {
//                    InetAddress ip = addresses.nextElement();
//                    if (!ip.isLoopbackAddress() && ip.getHostAddress().indexOf(':') == -1) {
//                        System.out.println(ni.getName() + " " + ip.getHostAddress());
//                    }
//                }
//            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
