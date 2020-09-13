package com.sniffer.UI;

import com.sniffer.UI.configWindow.CONFIG;
import com.sniffer.UI.configWindow.ConfigWindow;
import com.sniffer.net.PacketRepository;
import com.sniffer.net.SnifferThread;
import com.sniffer.util.FilePathHelper;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Callback;
import org.pcap4j.core.PcapPacket;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import static java.lang.Thread.sleep;

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
    private Button configButton;
    @FXML
    private Button saveDirectoryButton;
    @FXML
    private Label timeLabel;
    @FXML
    private Label ipLabel;
    @FXML
    private Button pauseButton;



    private SnifferThread mainThread;
    private ObservableList<PcapPacket> observableList = FXCollections.observableList(new ArrayList<PcapPacket>());
    private PacketRepository repo;
    private CONFIG mainConfig = CONFIG.getInstance();

    private boolean isListUpdate = true;


    public Controller(){

    }

    public void init(){

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

        System.out.println(mainConfig.getIpAddress());
        ipLabel.setText(mainConfig.getIpAddress());
        mainThread.start();
        timeUpdate();
        listUpdate();

    }

    private void bindSize(){

        menuBox.prefWidthProperty().bind(rootBox.widthProperty());
        menuBox.setPrefHeight(40);
        menuBox.spacingProperty().bind(rootBox.widthProperty().multiply(0.1));

        mainBox.prefWidthProperty().bind(rootBox.widthProperty());
        mainBox.prefHeightProperty().bind(rootBox.heightProperty().subtract(40));

        mainList.prefWidthProperty().bind(mainBox.widthProperty().multiply(0.7));
        mainList.prefHeightProperty().bind(mainBox.heightProperty());

        sideBox.prefWidthProperty().bind(mainBox.widthProperty().multiply(0.3));
        sideBox.prefHeightProperty().bind(mainBox.heightProperty());

        filterBox.prefHeightProperty().bind(sideBox.heightProperty().multiply(0.5));
        informationBox.prefHeightProperty().bind(sideBox.heightProperty().multiply(0.5));
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
                            observableList.add(temp);
                        });
                    }
                    try {
                        sleep(20);
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
                        timeLabel.setText(new SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss").format(new Date()));
                    });
                }
            }
        });
        timeUpdate.start();
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
            ipLabel.setText(mainConfig.getIpAddress());
        }catch (Exception e){
            e.printStackTrace();
        }

    }






}
