package com.sniffer.UI.configWindow;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.fxml.JavaFXBuilderFactory;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import java.net.URL;



/**
 * 参数配置窗口的Application类，是参数配置窗口建立的核心类
 * 在此类中加载了fxml文件并相应地加载了对应的controller类
 * @author wxy
 * @version 1.0
 */
public class ConfigWindow extends Application {

    public ConfigWindowController controller;

    @Override
    public void start(Stage primaryStage) throws Exception{
        URL location = getClass().getResource("configWindow.fxml");
        FXMLLoader fxmlLoader = new FXMLLoader();
        fxmlLoader.setLocation(location);
        fxmlLoader.setBuilderFactory(new JavaFXBuilderFactory());
        Parent root = fxmlLoader.load();

        primaryStage.setTitle("参数配置窗口");
        Scene scene = new Scene(root, 720, 310);
        primaryStage.setScene(scene);

        controller = fxmlLoader.getController();
        controller.init();

        primaryStage.show();
        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            @Override
            public void handle(WindowEvent event) {
                System.exit(0);
            }
        });
    }
}
