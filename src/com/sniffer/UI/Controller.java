package com.sniffer.UI;

import com.sniffer.UI.configWindow.CONFIG;
import com.sniffer.UI.configWindow.ConfigWindow;
import com.sniffer.net.PacketRepository;
import com.sniffer.net.SnifferThread;
import com.sniffer.util.DialogHelper;
import com.sniffer.util.FilePathHelper;
import com.sniffer.util.FormatHelper;
import com.sniffer.util.SearchHelper;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Callback;
import org.pcap4j.core.PcapPacket;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import static java.lang.Thread.sleep;


/**
 * 主窗口的Controller类，整个软件最核心的控制类，软件前后端数据交互主要在此进行
 * @author wxy
 * @version 1.8
 */
public class Controller {

    @FXML
    private VBox rootBox;
    @FXML
    private HBox menuBox;
    @FXML
    private HBox mainBox;
    @FXML
    private ListView mainList;
    @FXML
    private VBox sideBox;
    @FXML
    private VBox filterBox;
    @FXML
    private VBox informationBox;
    @FXML
    private TextArea detailArea;
    @FXML
    private Button configButton;
    @FXML
    private Button saveDirectoryButton;
    @FXML
    private Label timeLabel;
    @FXML
    private Label ipLabel;
    @FXML
    private Label numberLabel;
    @FXML
    private Label showNumberLabel;
    @FXML
    private Button pauseButton;
    @FXML
    private ComboBox filter_EtherProtocol;
    @FXML
    private ComboBox filter_DownProtocol;
    @FXML
    private TextField filter_srcIp;
    @FXML
    private TextField filter_dstIp;
    @FXML
    private TextField filter_allIp;
    @FXML
    private TextField filter_srcPort;
    @FXML
    private TextField filter_dstPort;



    private SnifferThread mainThread;
    private ObservableList<PcapPacket> observableList = FXCollections.observableList(new ArrayList<PcapPacket>());
    private ObservableList<PcapPacket> searchList = FXCollections.observableList(new ArrayList<PcapPacket>());
    private PacketRepository repo;
    private CONFIG mainConfig = CONFIG.getInstance();

    private boolean isListUpdate = true;
    private boolean isSearch = false;


    public Controller(){

    }

    public void init(){
        Application test = new ConfigWindow();
        Stage testStage = new Stage();
        try {
            test.start(testStage);
            System.out.printf("LOADING*******************************************************************");
        }catch (Exception e){
            e.printStackTrace();
        }
        testStage.show();


        bindSize();
        mainList.setCellFactory(new Callback<ListView<PcapPacket>, ListCell<PcapPacket>>() {
            @Override
            public ListCell call(ListView param) {
                return new PcapListCell();
            }
        });
        mainList.setItems(observableList);
        repo = PacketRepository.getInstance();

        try{
            mainThread = new SnifferThread();
            FilePathHelper.createSavePath();
        }catch (Exception e){
            e.printStackTrace();
        }
        detailArea.setWrapText(true);
        detailArea.setEditable(false);
        ipLabel.setText("适配器IP地址:" + mainConfig.getIpAddress());
        mainThread.start();
        timeUpdate();
        listUpdate();
        numberUpdate();
        showDetail();


        filter_EtherProtocol.getItems().setAll("---","IPv6","IPv4","ARP");
        filter_DownProtocol.getItems().setAll("---","TCP","UDP","IGMP","ICMP","DNS","HTTP(S)","IPV6_HOPOPT");
        filter_EtherProtocol.getSelectionModel().selectFirst();
        filter_DownProtocol.getSelectionModel().selectFirst();


        System.out.printf("SUCCESS***************************************************************");
        testStage.close();

    }

    private void bindSize(){

        menuBox.prefWidthProperty().bind(rootBox.widthProperty());
        menuBox.setPrefHeight(40);
        menuBox.spacingProperty().bind(rootBox.widthProperty().multiply(0.05));

        mainBox.prefWidthProperty().bind(rootBox.widthProperty());
        mainBox.prefHeightProperty().bind(rootBox.heightProperty().subtract(40));

        mainList.prefWidthProperty().bind(mainBox.widthProperty().multiply(0.75));
        mainList.prefHeightProperty().bind(mainBox.heightProperty());

        sideBox.prefWidthProperty().bind(mainBox.widthProperty().multiply(0.25));
        sideBox.prefHeightProperty().bind(mainBox.heightProperty());

        filterBox.prefHeightProperty().bind(sideBox.heightProperty().multiply(0.35));
        informationBox.prefHeightProperty().bind(sideBox.heightProperty().multiply(0.65));

        detailArea.prefHeightProperty().bind(informationBox.heightProperty().subtract(10));
        filter_dstIp.prefWidthProperty().bind(filterBox.widthProperty().multiply(0.6));
        filter_srcIp.prefWidthProperty().bind(filterBox.widthProperty().multiply(0.6));
        filter_allIp.prefWidthProperty().bind(filterBox.widthProperty().multiply(0.6));
        filter_dstPort.prefWidthProperty().bind(filterBox.widthProperty().multiply(0.4));
        filter_srcPort.prefWidthProperty().bind(filterBox.widthProperty().multiply(0.4));

    }

    private void listUpdate(){
        Platform.runLater(()->{
            observableList.clear();
        });
        Thread update = new Thread(new Runnable() {
            @Override
            public void run() {
                while (isListUpdate){
                    PcapPacket temp = repo.getItem();
                    if(temp != null){
                        Platform.runLater(()->{
                            if(isSearch){
                                try {
                                    if(SearchHelper.searchPacket(temp))
                                        searchList.add(temp);
                                }catch (UnknownHostException e){
                                    e.printStackTrace();
                                }
                            }
                            observableList.add(temp);
                        });
                    }
                    try {
                        sleep(1);
                    }catch (InterruptedException e){
                        e.printStackTrace();
                    }
                }
            }
        });
        update.start();
    }

    private void timeUpdate(){
        Thread timeUpdate = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true){
                    try{
                        sleep(1000);
                    }catch (InterruptedException e){
                        e.printStackTrace();
                    }
                    Platform.runLater(()->{
                        timeLabel.setText("系统时间:" + new SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss").format(new Date()));
                    });
                }
            }
        });
        timeUpdate.start();
    }
    private void numberUpdate(){
        Thread numberUpdate = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true){
                    try {
                        sleep(100);
                    }catch (InterruptedException e){
                        e.printStackTrace();
                    }
                    Platform.runLater(()->{
                        try {
                            numberLabel.setText("当前探测报文总数:" + Long.toString(mainThread.mainHandle.getStats().getNumPacketsCaptured()));
                            if(isSearch)
                                showNumberLabel.setText("已显示:"+Integer.toString(searchList.size()));
                            else
                                showNumberLabel.setText("已显示:"+Integer.toString(observableList.size()));
                        }catch (Exception e){
                            e.printStackTrace();
                        }

                    });
                }
            }
        });
        numberUpdate.start();
    }

    private void showDetail(){
        Thread detail = new Thread(new Runnable() {
            @Override
            public void run() {
                PcapPacket origin;
                origin = (PcapPacket)mainList.getSelectionModel().getSelectedItem();
                while (true){
                    PcapPacket temp = (PcapPacket)mainList.getSelectionModel().getSelectedItem();
                    if(temp != origin){
                        origin = temp;
                        Platform.runLater(()->{
                            if(temp != null)
                                detailArea.setText(FormatHelper.detailInformationFormat(temp));
                        });
                    }
                    try {
                        sleep(100);
                    }catch (InterruptedException e){
                        e.printStackTrace();
                    }
                }
            }
        });

        detail.start();
    }

    @FXML
    private void onPause(){
        if(mainThread.isPause()){
            mainThread.changePauseFlag();
            System.out.println("启动了！");
            pauseButton.setText("暂停");
        }else{
            mainThread.changePauseFlag();
            System.out.println("暂停了！");
            pauseButton.setText("启动");
        }
    }

    @FXML
    private void onDirectory(){
        try {
            Desktop.getDesktop().open(new File(FilePathHelper.PACKETSAVE_PATH));
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    @FXML
    private void onOpenConfig(){
        Application config = new ConfigWindow();
        Stage configStage = new Stage();
        try {
            mainThread.changeStopFlag();
            isListUpdate = false;
            config.start(configStage);
            configStage.showAndWait();
        }catch (Exception e){
            e.printStackTrace();
        }

        try{
            mainThread = new SnifferThread();
            FilePathHelper.createSavePath();
            mainThread.start();
            isListUpdate = true;
            listUpdate();
            pauseButton.setText("暂停");
            ipLabel.setText("适配器IP地址:" +mainConfig.getIpAddress());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @FXML
    private void filter_confirm(){
        SearchHelper.etherProtocol = (String)filter_EtherProtocol.getSelectionModel().getSelectedItem();
        SearchHelper.downProtocol = (String)filter_DownProtocol.getSelectionModel().getSelectedItem();
        if(!FormatHelper.checkIpAddress(filter_srcIp.getText()) | !FormatHelper.checkIpAddress(filter_dstIp.getText())
        | !FormatHelper.checkIpAddress(filter_allIp.getText())){
            DialogHelper.popErrorDialog("IP地址格式有误！");
            return;
        }
        if(!FormatHelper.checkPort(filter_srcPort.getText()) | !FormatHelper.checkPort(filter_dstPort.getText())){
            DialogHelper.popErrorDialog("端口号格式有误！");
            return;
        }

        SearchHelper.dstIp = filter_dstIp.getText();
        SearchHelper.srcIp = filter_srcIp.getText();
        SearchHelper.allIp = filter_allIp.getText();
        SearchHelper.dstPort = filter_dstPort.getText();
        SearchHelper.srcPort = filter_srcPort.getText();
        searchList.clear();

        for(int i = 0;i<observableList.size();i++){
            try {
                if(SearchHelper.searchPacket(observableList.get(i)))
                    searchList.add(observableList.get(i));
            }catch (UnknownHostException e){
                DialogHelper.popErrorDialog(e.getMessage());
            }
        }
        isSearch = true;
        mainList.setItems(searchList);
    }

    @FXML
    private void filter_cancel(){
        isSearch = false;
        mainList.setItems(observableList);
    }





}
