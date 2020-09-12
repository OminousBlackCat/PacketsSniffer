package com.sniffer.UI;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.fxml.JavaFXBuilderFactory;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.net.URL;

public class Main extends Application {

    private Controller controller;

    @Override
    public void start(Stage primaryStage) throws Exception{
        URL location = getClass().getResource("main.fxml");
        FXMLLoader fxmlLoader = new FXMLLoader();
        fxmlLoader.setLocation(location);
        fxmlLoader.setBuilderFactory(new JavaFXBuilderFactory());
        Parent root = fxmlLoader.load();


        primaryStage.setTitle("Packet Sniffer");
        primaryStage.setScene(new Scene(root, 1300, 800));
        primaryStage.show();

        controller = fxmlLoader.getController();
        controller.init();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
