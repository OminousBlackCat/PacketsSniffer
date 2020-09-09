package com.sniffer.net;

import com.sniffer.UI.configWindow.CONFIG;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * 后端主线程类，建立抓包线程
 * @author wxy
 * @version 1.0
 * */
public class SnifferThread extends Thread {

    private InetAddress ip;
    private PcapNetworkInterface sniffer;
    private PcapHandle mainHandle;
    private PcapNetworkInterface.PromiscuousMode mode;
    private int snapLen = 65536;
    private int timeout = 10;
    private int localPacketNumber = 2000;

    private CONFIG config;

    /**
     * 构造函数，从config中获取参数之后直接建立handle，此后便可以开启线程
     * @exception PcapNativeException on handle set error
     * @exception UnknownHostException on ipAddress set error
     * @see PcapNativeException
     * @see UnknownHostException
     * */
    public SnifferThread() throws PcapNativeException,UnknownHostException{
        readConfig();
        sniffer = Pcaps.getDevByAddress(ip);
        mainHandle = sniffer.openLive(snapLen,mode,timeout);
    }

    private void readConfig() throws UnknownHostException {
        config = CONFIG.getInstance();
        ip = InetAddress.getByName(config.getIpAddress());
        mode = config.getMode();
        snapLen = config.getSnapLen();
        timeout = config.getTimeout();
    }

    @Override
    public void run(){



    }
}
