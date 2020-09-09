package com.sniffer.net;

import com.sniffer.util.FileHelper;
import com.sniffer.util.FilePathHelper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;

import java.io.File;
import java.net.InetAddress;

import static java.lang.Thread.dumpStack;
import static java.lang.Thread.sleep;

public class SnifferTest {

    public static void main(String args[]){

        try {
            InetAddress addr = InetAddress.getByName("10.201.36.163");
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
                    System.out.println(temp.getPacket());
                    FileHelper.appendLine(FilePathHelper.PACKETSAVE_PATH + File.separator + "1.txt",temp);
                }
                sleep(1000);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
