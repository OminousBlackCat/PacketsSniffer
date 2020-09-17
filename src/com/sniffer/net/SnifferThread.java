package com.sniffer.net;

import com.sniffer.UI.configWindow.CONFIG;
import com.sniffer.util.FileHelper;
import com.sniffer.util.FilePathHelper;
import org.pcap4j.core.*;

import java.io.File;
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
    public PcapHandle mainHandle;
    private PcapNetworkInterface.PromiscuousMode mode;
    private PacketRepository repository;
    private int snapLen = 65536;
    private int timeout = 10;
    private int count = 0;
    private int fileCount = 1;
    private boolean isPause = false;
    private boolean isStop = false;

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
        repository = PacketRepository.getInstance();
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

    public void changePauseFlag(){
        isPause = !isPause;
    }
    public boolean isPause(){
        return isPause;
    }

    public void changeStopFlag(){
        isStop = !isStop;
    }

    public boolean isStop(){
        return isStop;
    }

    @Override
    public void run(){
        try {
            repository.clearRepo();
            while (!isStop){
                if(!isPause){
                    PcapPacket temp = mainHandle.getNextPacket();
                    if(temp != null){
                        count ++;
                        if(count > config.getRepoNumber()){
                            count = 0;
                            fileCount ++;
                            repository.clearRepo();
                        }
                        repository.addItem(temp);
                        FileHelper.appendLine(FilePathHelper.PACKETSAVE_PATH + File.separator +Integer.toString(fileCount)+ ".txt",temp);
                    }
                }else {
                    PcapPacket temp = mainHandle.getNextPacket();
                }
            }
        }catch (Exception noe){
            noe.printStackTrace();
        }
    }
}
