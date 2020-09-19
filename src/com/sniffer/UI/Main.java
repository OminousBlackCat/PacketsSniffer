package com.sniffer.UI;

import com.sniffer.UI.configWindow.ConfigWindow;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.fxml.JavaFXBuilderFactory;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.File;
import java.net.URL;


/**
 * 主窗口类，继承Application，通过fmxl构造窗口，实例化controller
 * @author wxy
 * @version 1.0
 */
public class Main extends Application {

    private Controller controller;

    @Override
    public void start(Stage primaryStage) throws Exception{

        Application config = new ConfigWindow();
        Stage configStage = new Stage();
        config.start(configStage);
        configStage.showAndWait();



        URL location = getClass().getResource("main.fxml");
        FXMLLoader fxmlLoader = new FXMLLoader();
        fxmlLoader.setLocation(location);
        fxmlLoader.setBuilderFactory(new JavaFXBuilderFactory());
        Parent root = fxmlLoader.load();


        primaryStage.setTitle("Packet Sniffer");
        primaryStage.setScene(new Scene(root, 1600, 800));
        primaryStage.setMinHeight(400);
        primaryStage.setMinWidth(900);
        primaryStage.getIcons().add(new Image("file:" + System.getProperty("user.dir") + File.separator + "icon.png"));
        primaryStage.show();

        controller = fxmlLoader.getController();
        controller.init();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
