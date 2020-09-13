package com.sniffer.UI.configWindow;

import org.pcap4j.core.PcapNetworkInterface;


/**
 * 单例类，传递net.snifferThread需要的config
 * @author wxy
 * @version 1.0
 */
public class CONFIG {
    private static CONFIG instance = new CONFIG();

    private String ipAddress = "192.168.1.102";  //适配器ip地址
    private int snapLen = 65536;                 //报文最大长度
    private int timeout = 1000;                  //抓取周期
    private PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;   //适配器工作模式
    private int repoNumber = 1000;               //本地仓库缓存报文上限



    private CONFIG(){}

    /**
     * 获取CONFIG唯一实例
     * @return CONFIG
     * */
    public static CONFIG getInstance(){
        return instance;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public int getSnapLen() {
        return snapLen;
    }

    public void setSnapLen(int snapLen) {
        this.snapLen = snapLen;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public PcapNetworkInterface.PromiscuousMode getMode() {
        return mode;
    }

    public void setMode(PcapNetworkInterface.PromiscuousMode mode) {
        this.mode = mode;
    }

    public int getRepoNumber() {
        return repoNumber;
    }

    public void setRepoNumber(int repoNumber) {
        this.repoNumber = repoNumber;
    }
}
