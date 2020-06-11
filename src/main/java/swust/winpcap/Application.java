package swust.winpcap;

import java.awt.EventQueue;

import javax.swing.UIManager;

/**
 * 
 * 启动类
 *
 * @author xuLiang
 * @since 1.0.0
 */
public class Application {
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                    new MainWindow();
                    MainWindow.mainFrame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
