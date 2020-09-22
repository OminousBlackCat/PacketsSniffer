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

/**
 * 对表格单元类的派生，自定义了表格单元并以此来显示不同类型的报文，主要逻辑在方法updateItem内
 * @author wxy
 * @version 1.6
 */
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

        ipClassImg.setPrefWidth(40);
        transClassImg.setPrefWidth(70);
        appClassImg.setPrefWidth(60);


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
                    appClassImg.setText("----");
                    sourceIpLabel.setPrefWidth(140);
                    destinyIpLabel.setPrefWidth(140);
                    sourceIpLabel.setText("F:" + temp.getHeader().getSrcAddr().getHostAddress());
                    destinyIpLabel.setText("T:" + temp.getHeader().getDstAddr().getHostAddress());

                    if(temp.getHeader().getProtocol() == IpNumber.TCP){
                        TcpPacket tcpPacket = temp.get(TcpPacket.class);
                        transClassImg.setText("TCP");
                        sourcePortLabel.setText("F:" + tcpPacket.getHeader().getSrcPort().toString());
                        destinyPortLabel.setText("T:" + tcpPacket.getHeader().getDstPort().toString());
                        if(tcpPacket.getHeader().getDstPort() == TcpPort.HTTPS ||
                                tcpPacket.getHeader().getSrcPort() == TcpPort.HTTPS ||
                                tcpPacket.getHeader().getDstPort() == TcpPort.HTTP ||
                                tcpPacket.getHeader().getSrcPort() == TcpPort.HTTP){
                            cellBox.setStyle("-fx-background-color: #f5ff9b");
                            appClassImg.setText("HTTP(S)");
                        }else {
                            cellBox.setStyle("-fx-background-color: #a6ff7f");
                            appClassImg.setText("----");
                        }
                    } else if(temp.getHeader().getProtocol() == IpNumber.UDP){
                        UdpPacket udpPacket = temp.get(UdpPacket.class);
                        transClassImg.setText("UDP");
                        sourcePortLabel.setText("F:" + udpPacket.getHeader().getSrcPort().toString());
                        destinyPortLabel.setText("T:" + udpPacket.getHeader().getDstPort().toString());
                        if(temp.get(DnsPacket.class) != null){
                            cellBox.setStyle("-fx-background-color: #ffac66");
                            appClassImg.setText("DNS");
                        }else if(udpPacket.getHeader().getSrcPort().value() == 8000 ||
                                udpPacket.getHeader().getDstPort().value() == 8000 ||
                                udpPacket.getHeader().getSrcPort().value() == 8001 ||
                                udpPacket.getHeader().getDstPort().value() == 8001){
                            cellBox.setStyle("-fx-background-color: #ff7193");
                            appClassImg.setText("OICQ");
                        }else {
                            cellBox.setStyle("-fx-background-color: #ff94dd");
                        }
                    } else if(temp.getHeader().getProtocol() == IpNumber.IGMP){
                        transClassImg.setText("IGMP");
                        cellBox.setStyle("-fx-background-color: #ff2b2a");
                    } else if(temp.getHeader().getProtocol() == IpNumber.ICMPV4){
                        transClassImg.setText("ICMPv4");
                        cellBox.setStyle("-fx-background-color: #e4abff");
                    } else{
                        transClassImg.setText(temp.getHeader().getProtocol().toString());
                        cellBox.setStyle("-fx-background-color: #ff2b2a");
                    }
                }
                else if(ePacket.getHeader().getType() == EtherType.IPV6){
                    appClassImg.setText("---");
                    ipClassImg.setText("IPV6");
                    sourceIpLabel.setPrefWidth(250);
                    destinyIpLabel.setPrefWidth(250);
                    IpV6Packet temp = ePacket.get(IpV6Packet.class);
                    sourceIpLabel.setText("F:" + temp.getHeader().getSrcAddr().getHostAddress());
                    destinyIpLabel.setText("T:" + temp.getHeader().getDstAddr().getHostAddress());

                    if(temp.getHeader().getProtocol() == IpNumber.ICMPV6){
                        transClassImg.setText("ICMPv6");
                        cellBox.setStyle("-fx-background-color: #c97cff");
                    }else if(temp.getHeader().getProtocol() == IpNumber.IPV6_HOPOPT){
                        cellBox.setStyle("-fx-background-color: #736fff");
                        transClassImg.setText("HOPOPT");
                    }else if(temp.getHeader().getProtocol() == IpNumber.UDP){
                        cellBox.setStyle("-fx-background-color: #cb66a7");
                        transClassImg.setText("UDP");
                    }else if (temp.getHeader().getProtocol() == IpNumber.TCP){
                        cellBox.setStyle("-fx-background-color: #8bd66e");
                        transClassImg.setText("TCP");
                        TcpPacket tTemp = temp.get(TcpPacket.class);
                        if(tTemp.getHeader().getDstPort() == TcpPort.HTTPS ||
                                tTemp.getHeader().getSrcPort() == TcpPort.HTTPS ||
                                tTemp.getHeader().getDstPort() == TcpPort.HTTP ||
                                tTemp.getHeader().getSrcPort() == TcpPort.HTTP) {
                            cellBox.setStyle("-fx-background-color: #d0d883");
                            appClassImg.setText("HTTP(S)");
                        }
                    }else {
                        transClassImg.setText(temp.getHeader().getProtocol().toString());
                        cellBox.setStyle("-fx-background-color: #ff2b2a");
                    }

                    if(temp.get(DnsPacket.class) != null){
                        cellBox.setStyle("-fx-background-color: #e39065");
                        appClassImg.setText("DNS(IPV6)");
                    }

                }

                else if(ePacket.getHeader().getType() == EtherType.ARP){
                    appClassImg.setText("---");
                    ipClassImg.setText("ARP");
                    transClassImg.setText("---");
                    sourceIpLabel.setPrefWidth(140);
                    destinyIpLabel.setPrefWidth(140);
                    ArpPacket temp = ePacket.get(ArpPacket.class);
                    cellBox.setStyle("-fx-background-color: #bfbfbf");
                    sourceIpLabel.setText( temp.getHeader().getSrcProtocolAddr().getHostAddress());
                    destinyIpLabel.setText(temp.getHeader().getDstProtocolAddr().getHostAddress());

                    sourceMacLabel.setText(ePacket.getHeader().getSrcAddr().toString());
                    destinyMacLabel.setText(ePacket.getHeader().getDstAddr().toString());
                }

            }catch (Exception e){
                e.printStackTrace();
            }
            setGraphic(cellBox);
        }else
            setGraphic(null);
    }
}
