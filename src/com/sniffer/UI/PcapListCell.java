package com.sniffer.UI;

import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.layout.HBox;
import org.pcap4j.core.PcapPacket;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;





public class PcapListCell extends ListCell<PcapPacket> {

    private HBox cellBox;
    private Label timeLabel;
    private Label ipClassImg;
    private Label transClassImg;
    private Label payloadLabel;
    private Label sourceLabel;
    private Label destinyLabel;

    public PcapListCell(){
        super();

        cellBox = new HBox();
        timeLabel = new Label();
        ipClassImg = new Label();///
        transClassImg = new Label();///
        payloadLabel = new Label();
        sourceLabel = new Label();
        destinyLabel = new Label();

        cellBox.getChildren().add(timeLabel);
        cellBox.getChildren().add(ipClassImg);
        cellBox.getChildren().add(transClassImg);
        cellBox.getChildren().add(payloadLabel);
        cellBox.getChildren().add(sourceLabel);
        cellBox.getChildren().add(destinyLabel);
        cellBox.setSpacing(10);

    }


    @Override
    protected void updateItem(PcapPacket item,boolean empty){
        super.updateItem(item,empty);

        Properties etherProperties = new Properties();
        Properties ipProperties = new Properties();
        boolean isIpv4 = false;



        if(item != null && !empty){
            try{
                etherProperties.load(new ByteArrayInputStream(item.getPacket().getHeader().toString().getBytes()));
                ipProperties.load(new ByteArrayInputStream(item.getPacket().getPayload().getHeader().toString().getBytes()));
            }catch (IOException ioe){
                ioe.printStackTrace();
            }

            try{
                timeLabel.setText(item.getTimestamp().toString());

                switch (etherProperties.getProperty("Type")){  ////此处应该封装为一个函数在FormatHelper里
                    case "0x0806 (ARP)":
                        ipClassImg.setText("ARP");
                        isIpv4 = false;
                        break;
                    case "0x86dd (IPv6)":
                        ipClassImg.setText("IPv6");
                        isIpv4 = false;
                        break;
                    case "0x0800 (IPv4)":
                        ipClassImg.setText("IPv4");
                        isIpv4 = true;
                        break;
                }

                if(isIpv4){
                    if(ipProperties.getProperty("Protocol").equals("17 (UDP)")){
                        transClassImg.setText("UDP"); ///
                    }else
                        transClassImg.setText("TCP");
                }else {
                    transClassImg.setText("---");
                }

                sourceLabel.setText(ipProperties.getProperty("Source"));
                destinyLabel.setText(ipProperties.getProperty("Destination"));
            }catch (Exception e){
                e.printStackTrace();
            }
            setGraphic(cellBox);
        }else
            setGraphic(null);
    }
}
