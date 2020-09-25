package com.sniffer.UI.configWindow;

import com.sniffer.util.DialogHelper;
import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.fxml.JavaFXBuilderFactory;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.io.File;
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
        primaryStage.getIcons().add(new Image("file:" + System.getProperty("user.dir") + File.separator + "icon.png"));

        controller = fxmlLoader.getController();
        controller.init();

        //primaryStage.show();
        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            @Override
            public void handle(WindowEvent event) {
                if(DialogHelper.popConfirmationDialog("确定","是否退出？"))
                    System.exit(0);
                else
                    event.consume();
            }
        });
    }
}
