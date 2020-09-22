package com.sniffer.util;

import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.Region;

import java.util.Optional;



/**
 * 使用此类来包装所有与弹出窗口相关的操作
 * @author wxy
 * @version 1.0
 */
public class DialogHelper {

    public static void popErrorDialog(String content){
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                DialogHelper.popWarningDialog("错误提示",content);
            }
        });
    }
    public static void popWarningDialog(String header, String context) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("警告");
        alert.setHeaderText(header);
        alert.setContentText(context);

        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.showAndWait();
    }

    public static void popInformationDialog(String header, String context) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("提示");
        alert.setHeaderText(header);
        alert.setContentText(context);

        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);

        alert.showAndWait();
    }

    public static boolean popConfirmationDialog(String header,String context){
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("请确认");
        alert.setHeaderText(header);
        alert.setContentText(context);

        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);

        Optional<ButtonType> result = alert.showAndWait();
        if (result.get() == ButtonType.OK){
            return true;
        } else {
            return false;
        }
    }


}
