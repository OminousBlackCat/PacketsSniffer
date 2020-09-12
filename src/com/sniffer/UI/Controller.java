package com.sniffer.UI;

import com.sniffer.net.PacketRepository;
import com.sniffer.net.SnifferThread;
import com.sniffer.util.FilePathHelper;
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
import javafx.util.Callback;
import org.pcap4j.core.PcapPacket;

import java.util.ArrayList;

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
    private Button pauseButton;

    private SnifferThread mainThread;
    private ObservableList<PcapPacket> observableList = FXCollections.observableList(new ArrayList<PcapPacket>());
    private PacketRepository repo;


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

        mainThread.start();
        listUpdate();

    }

    private void bindSize(){
        menuBox.prefWidthProperty().bind(rootBox.widthProperty());
        menuBox.setPrefHeight(40);

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

        Thread update = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true){
                    PcapPacket temp = repo.getItem();
                    if(temp != null){
                        Platform.runLater(()->{
                            observableList.add(temp);
                        });
                    }
                    try {
                        sleep(50);
                    }catch (InterruptedException e){
                        e.printStackTrace();
                    }
                }
            }
        });

        update.start();

    }

    @FXML
    private void onPause(){
        if(mainThread.isPause()){
            mainThread.changeFlag();
            System.out.println("启动了！");
            pauseButton.setText("暂停");
        }else{
            mainThread.changeFlag();
            System.out.println("暂停了！");
            pauseButton.setText("启动");
        }
    }






}
