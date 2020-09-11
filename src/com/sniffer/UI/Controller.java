package com.sniffer.UI;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

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


    public Controller(){

    }

    public void init(){
        bindSize();
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






}
