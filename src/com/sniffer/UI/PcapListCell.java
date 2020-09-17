package com.sniffer.UI;

import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.layout.Background;
import javafx.scene.layout.HBox;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;


public class PcapListCell extends ListCell<PcapPacket> {

    private HBox cellBox;
    private Label timeLabel;
    private Label ipClassImg;
    private Label transClassImg;
    private Label payloadLabel;
    private Label sourceMacLabel;
    private Label destinyMacLabel;
    private Label sourceIpLabel;
    private Label destinyIpLabel;
    private Label appClassImg;
    private Label sourcePortLabel;
    private Label destinyPortLabel;

    public PcapListCell(){
        super();

        cellBox = new HBox();
        timeLabel = new Label();
        ipClassImg = new Label();///
        transClassImg = new Label();///
        appClassImg = new Label();
        payloadLabel = new Label();
        sourceMacLabel = new Label();
        destinyMacLabel = new Label();
        sourceIpLabel = new Label();
        destinyIpLabel = new Label();
        sourcePortLabel = new Label();
        destinyPortLabel = new Label();



        cellBox.getChildren().add(timeLabel);
        cellBox.getChildren().add(ipClassImg);
        cellBox.getChildren().add(transClassImg);
        cellBox.getChildren().add(appClassImg);
        cellBox.getChildren().add(payloadLabel);
        cellBox.getChildren().add(sourceMacLabel);
        cellBox.getChildren().add(destinyMacLabel);
        cellBox.getChildren().add(sourceIpLabel);
        cellBox.getChildren().add(destinyIpLabel);
        cellBox.getChildren().add(sourcePortLabel);
        cellBox.getChildren().add(destinyPortLabel);
        cellBox.setSpacing(10);

    }


    @Override
    protected void updateItem(PcapPacket item,boolean empty){
        super.updateItem(item,empty);

        if(item != null && !empty){

            EthernetPacket ePacket = item.get(EthernetPacket.class);

            try{
                timeLabel.setText(item.getTimestamp().atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm:ss:SSS")));
                sourceMacLabel.setText("");
                destinyMacLabel.setText("");
                sourcePortLabel.setText("");
                destinyPortLabel.setText("");



                if(ePacket.getHeader().getType() == EtherType.IPV4){
                    ipClassImg.setText("IPV4");
                    IpV4Packet temp = ePacket.get(IpV4Packet.class);
                    sourceIpLabel.setText(temp.getHeader().getSrcAddr().toString());
                    destinyIpLabel.setText(temp.getHeader().getDstAddr().toString());

                    if(temp.getHeader().getProtocol() == IpNumber.TCP){
                        TcpPacket tcpPacket = temp.get(TcpPacket.class);
                        sourcePortLabel.setText(tcpPacket.getHeader().getSrcPort().toString());
                        destinyPortLabel.setText(tcpPacket.getHeader().getDstPort().toString());
                        if(tcpPacket.getHeader().getDstPort() == TcpPort.HTTPS ||
                                tcpPacket.getHeader().getSrcPort() == TcpPort.HTTPS ||
                                tcpPacket.getHeader().getDstPort() == TcpPort.HTTP ||
                                tcpPacket.getHeader().getSrcPort() == TcpPort.HTTP){
                            cellBox.setStyle("-fx-background-color: #f5ff9b");
                            appClassImg.setText("HTTP(S)");
                        }else {
                            cellBox.setStyle("-fx-background-color: #d1b0ff");
                            appClassImg.setText("----");
                        }
                    }
                    else{
                        if(temp.getHeader().getProtocol() == IpNumber.UDP){
                            UdpPacket udpPacket = temp.get(UdpPacket.class);
                            sourcePortLabel.setText(udpPacket.getHeader().getSrcPort().toString());
                            destinyPortLabel.setText(udpPacket.getHeader().getDstPort().toString());
                            if(temp.get(DnsPacket.class) != null){
                                cellBox.setStyle("-fx-background-color: #ffa762");
                                appClassImg.setText("DNS");
                            }else {
                                cellBox.setStyle("-fx-background-color: #ff94dd");
                                appClassImg.setText("---");
                            }
                        } else
                            cellBox.setStyle("-fx-background-color: #ff8080");
                    }
                }

                if(ePacket.getHeader().getType() == EtherType.IPV6){
                    appClassImg.setText("");

                    ipClassImg.setText("IPV6");
                    IpV6Packet temp = ePacket.get(IpV6Packet.class);
                    sourceIpLabel.setText(temp.getHeader().getSrcAddr().toString());
                    destinyIpLabel.setText(temp.getHeader().getDstAddr().toString());

                    if(temp.get(DnsPacket.class) != null){
                        cellBox.setStyle("-fx-background-color: #ffa762");
                        appClassImg.setText("DNS(IPV6)");
                    }else {
                        cellBox.setStyle("-fx-background-color: #adff81");
                    }

                }

                if(ePacket.getHeader().getType() == EtherType.ARP){
                    appClassImg.setText("");

                    ipClassImg.setText("ARP");
                    ArpPacket temp = ePacket.get(ArpPacket.class);
                    cellBox.setStyle("-fx-background-color: #bfbfbf");
                    sourceIpLabel.setText(temp.getHeader().getSrcProtocolAddr().toString());
                    destinyIpLabel.setText(temp.getHeader().getDstProtocolAddr().toString());

                    sourceMacLabel.setText(ePacket.getHeader().getSrcAddr().toString());
                    destinyMacLabel.setText(ePacket.getHeader().getDstAddr().toString());
                }


                transClassImg.setText("---");
                if(ePacket.get(TcpPacket.class) != null)
                    transClassImg.setText("TCP");
                if(ePacket.get(UdpPacket.class) != null)
                    transClassImg.setText("UDP");


            }catch (Exception e){
                e.printStackTrace();
            }
            setGraphic(cellBox);
        }else
            setGraphic(null);
    }
}
