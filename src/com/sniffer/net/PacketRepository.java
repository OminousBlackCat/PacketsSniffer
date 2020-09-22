package com.sniffer.net;

import org.pcap4j.core.PcapPacket;

import java.util.ArrayList;
import java.util.List;


/**
 * 前后端线程交互所用的数据结构，存放所有抓取到的报文
 * @author wxy
 * @version 1.0
 * */
public class PacketRepository {
    private static PacketRepository instance = new PacketRepository();
    private List<PcapPacket> repo;
    private int pointer;

    private PacketRepository(){
        repo = new ArrayList<>();
        pointer = 0;
    }

    public List<PcapPacket> getRepo(){
        return repo;
    }
    public int getPointer(){
        return pointer;
    }
    public void addItem(PcapPacket packet){
        repo.add(packet);
    }
    public PcapPacket getItem(){
        if(pointer >= repo.size()){
            return null;
        }
        return repo.get(pointer++);
    }
    public void clearRepo(){
        pointer = 0;
        repo.clear();
    }

    public static PacketRepository getInstance(){
        return instance;
    }

}
