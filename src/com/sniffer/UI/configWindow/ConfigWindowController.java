package com.sniffer.UI.configWindow;

import com.sniffer.util.DialogHelper;
import com.sniffer.util.FilePathHelper;
import com.sniffer.util.FormatHelper;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.pcap4j.core.PcapNetworkInterface;

import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.Properties;


/**
 * 参数配置窗口的Controller类，包含了参数配置窗口的前端逻辑
 * @author wxy
 * @version 1.0
 */
public class ConfigWindowController {


    @FXML
    private VBox rootBox;
    @FXML
    private TextField configFilePath;
    @FXML
    private Button configFileChoose;
    @FXML
    private ComboBox nicWorkMode;
    @FXML
    private ComboBox nicIpAddress;
    @FXML
    private TextField snapLength;
    @FXML
    private TextField snapTimeout;
    @FXML
    private Button confirmButton;
    @FXML
    private Button cancelButton;

    private File configFile;
    private InputStream configFileStream;
    private Properties properties = new Properties();
    private boolean isFirstSet = true;
    private CONFIG config;



    public ConfigWindowController(){

    }

    public void init(){
        config = CONFIG.getInstance();
        nicWorkMode.getItems().setAll("混杂模式","非混杂模式");
        try {
            configFile = new File(FilePathHelper.CONFIG_PATH);
            if(!configFile.exists()){
                isFirstSet = true;
                configFile.createNewFile();
            }else {
                isFirstSet = false;
                configFileStream = new FileInputStream(configFile);
                configFilePath.setText(configFile.getAbsolutePath());
            }
            importConfig();
        }catch (IOException ioe){
            ioe.printStackTrace();
        }
    }

    private void importConfig() throws IOException {
        Enumeration<NetworkInterface> netInterfaces;
        netInterfaces = NetworkInterface.getNetworkInterfaces();
        while (netInterfaces.hasMoreElements()) {
            NetworkInterface ni = netInterfaces.nextElement();
            Enumeration<InetAddress> addresses = ni.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress ip = addresses.nextElement();
                if (!ip.isLoopbackAddress() && ip.getHostAddress().indexOf(':') == -1) {
                    nicIpAddress.getItems().add(ip.getHostAddress() + "/" + FormatHelper.getNICName(ni.getName()));
                }
            }
        }
        nicIpAddress.getSelectionModel().selectFirst();


        if(isFirstSet){
            nicWorkMode.getSelectionModel().selectFirst();
            snapTimeout.setText("20");
            snapLength.setText("65536");
        }else{
            properties.load(configFileStream);
            if(properties.getProperty("nicWorkMode") == null || properties.getProperty("SnapLength") == null ||
                    properties.getProperty("SnapTimeout") == null){
                DialogHelper.popErrorDialog("配置文件格式有误！将以默认参数配置程序！");

                nicWorkMode.getSelectionModel().selectFirst();
                snapTimeout.setText("20");
                snapLength.setText("65536");
                /**
                 *
                 *
                 * */
                return;
            }
            if(properties.getProperty("nicWorkMode").equals("PROMISCUOUS"))
                nicWorkMode.getSelectionModel().selectFirst();
            else
                nicWorkMode.getSelectionModel().select(1);

            snapLength.setText(properties.getProperty("SnapLength"));
            snapTimeout.setText(properties.getProperty("SnapTimeout"));

        }
    }

    @FXML
    public void onFileChoose(){
        FileChooser fileChooser;

        fileChooser = new FileChooser();
        fileChooser.setTitle("Choose File");
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));

        configFile = fileChooser.showOpenDialog(rootBox.getScene().getWindow());
        if (configFile!= null) {
            try {
                configFilePath.setText(configFile.getAbsolutePath());
                configFileStream = new FileInputStream(configFile);
            }catch (FileNotFoundException fnfe){
                fnfe.printStackTrace();
            }
        }
        try {
            importConfig();
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    @FXML
    public void onConfirm(){
        config.setIpAddress(nicIpAddress.getSelectionModel().getSelectedItem().toString().split("/")[0]);
        if(FormatHelper.checkSnapLength(snapLength.getText())){
            config.setSnapLen(Integer.parseInt(snapLength.getText()));
        }else {
            DialogHelper.popErrorDialog("探测报文长度格式有误！请确保长度在0~65536范围内！");
            return;
        }
        if(FormatHelper.checkSnapTimeout(snapTimeout.getText())){
            config.setTimeout(Integer.parseInt(snapTimeout.getText()));
        }else {
            DialogHelper.popErrorDialog("探测周期格式有误！请确保周期在10~10000范围内！");
            return;
        }

        switch (nicWorkMode.getSelectionModel().getSelectedIndex()){
            case 0:
                config.setMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS);
                break;
            case 1:
                config.setMode(PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS);
                break;
        }
        final Stage stage =(Stage)rootBox.getScene().getWindow();
        stage.close();
    }

    @FXML
    public void onCancel(){
        DialogHelper.popConfirmationDialog("确认？","是否退出程序？");
        System.exit(0);
    }


}
