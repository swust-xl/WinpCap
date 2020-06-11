package swust.winpcap;

import javax.swing.JFrame;
import java.awt.Toolkit;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import java.awt.Font;
import javax.swing.JMenuItem;
import javax.swing.KeyStroke;
import java.awt.event.*;
import java.util.ArrayList;

import javax.swing.JScrollPane;
import javax.swing.JPanel;
import javax.swing.JTextPane;
import java.awt.Color;
import javax.swing.JList;
import javax.swing.JTextArea;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.jnetpcap.PcapIf;
import javax.swing.JLabel;
import java.awt.BorderLayout;

/**
 * 主窗体界面
 * 
 */
public class MainWindow {

    public static JFrame mainFrame;
    public static DefaultListModel<String> listModel = new DefaultListModel<>();
    private JList<String> list = new JList<>(listModel);

    public static JPanel chartArea;// 下右部分的图形区域，图形的方式显示统计结果
    public static JTextArea statisticsTextArea;// 左下角文本域
    public static JTextArea detailTextArea;// 中右部分的文本域

    public static final String CMD_START = "start";
    public static final String CMD_STOP = "stop";
    public static final String CMD_CLEAN = "clean";
    public static final String CMD_ANALYSE = "analyse";
    public static final String CMD_SAVE = "save";
    public static final String CMD_PAINT = "paint";

    /**
     * Create the application.
     */
    public MainWindow() {

        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        mainFrame = new JFrame(); // 主窗体
        Listener listener = new Listener();// 监听器
        mainFrame.getContentPane()
                .setBackground(Color.WHITE);
        mainFrame.setResizable(false);
        mainFrame.setIconImage(Toolkit.getDefaultToolkit()
                .getImage("imgs\\5.jpg"));
        mainFrame.setTitle("WinPcap\u6D41\u91CF\u5206\u6790\u5668");
        mainFrame.setBounds(100, 100, 900, 700);
        mainFrame.setLocationRelativeTo(null);
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainFrame.getContentPane()
                .setLayout(null);

        // 菜单栏
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBounds(0, 0, 900, 30);
        mainFrame.getContentPane()
                .add(menuBar);

        // “抓包”菜单
        JMenu menu0 = new JMenu("\u6293\u5305(Z)");
        menu0.setMnemonic('Z');
        menu0.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        menuBar.add(menu0);

        // “开始抓包”菜单项
        JMenuItem mi_startCap = new JMenuItem("\u5F00\u59CB\u6293\u5305(B)");
        mi_startCap.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('B');
        mi_startCap.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_MASK));
        menu0.add(mi_startCap);
        mi_startCap.setActionCommand(CMD_START);
        mi_startCap.addActionListener(listener);

        // “结束抓包”菜单项
        JMenuItem mi_endCap = new JMenuItem("\u7ED3\u675F\u6293\u5305(E)");
        mi_endCap.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('E');
        mi_endCap.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_MASK));
        menu0.add(mi_endCap);
        mi_endCap.setActionCommand(CMD_STOP);
        mi_endCap.addActionListener(listener);

        // “清空记录”菜单项
        JMenuItem mi_clean = new JMenuItem("\u6E05\u7A7A\u8BB0\u5F55(C)");
        mi_clean.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('C');
        mi_clean.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_MASK));
        menu0.add(mi_clean);
        mi_clean.setActionCommand(CMD_CLEAN);
        mi_clean.addActionListener(listener);

        // “统计结果”菜单
        JMenu menu1 = new JMenu("\u7EDF\u8BA1\u7ED3\u679C(X)");
        menu1.setMnemonic('X');
        menu1.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        menuBar.add(menu1);

        // “图形显示”菜单项
        JMenuItem mi_tuxing = new JMenuItem("\u56FE\u5F62\u663E\u793A(T)");
        mi_tuxing.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('T');
        mi_tuxing.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_MASK));
        menu1.add(mi_tuxing);
        mi_tuxing.setActionCommand(CMD_PAINT);
        mi_tuxing.addActionListener(listener);

        // “保存结果”菜单项
        JMenuItem mi_save = new JMenuItem("\u4FDD\u5B58\u7ED3\u679C(S)");
        mi_save.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('S');
        mi_save.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_MASK));
        menu1.add(mi_save);
        mi_save.setActionCommand(CMD_SAVE);
        mi_save.addActionListener(listener);

        // “帮助”菜单
        JMenu menu2 = new JMenu("\u5E2E\u52A9(H)");
        menu2.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        menu2.setMnemonic('H');
        menuBar.add(menu2);

        // “结果分析”菜单项
        JMenuItem mi_about = new JMenuItem("\u7ed3\u679c\u5206\u6790(A)");
        mi_about.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        mi_startCap.setMnemonic('A');
        mi_about.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_MASK));
        menu2.add(mi_about);
        mi_about.setActionCommand(CMD_ANALYSE);
        mi_about.addActionListener(listener);

        // 中左部分的显示框滚动条
        JScrollPane leftScrollPane = new JScrollPane();
        leftScrollPane.setBounds(0, 58, 169, 387);
        mainFrame.getContentPane()
                .add(leftScrollPane);
        // 中左部分的显示列表
        leftScrollPane.setViewportView(list);
        list.addListSelectionListener(new ListSelectionListener() {// 点击list项在中右部分显示具体信息
            @Override
            public void valueChanged(ListSelectionEvent e) {
                detailTextArea.setText("");
                detailTextArea.append(PacketHandler.map.get(list.getSelectedIndex()));// 从hashmap取数据
            }
        });

        // 中间部分的“详细信息文字显示”
        JLabel label = new JLabel("<html>详<br/>细<br/>信<br/>息<br/></html>");
        label.setFont(new Font("Microsoft JhengHei", Font.PLAIN, 15));
        label.setBounds(177, 155, 18, 112);
        mainFrame.getContentPane()
                .add(label);

        // 中右部分的显示的滚动条
        JScrollPane rightScrollPane = new JScrollPane();
        rightScrollPane.setBounds(194, 58, 675, 387);
        mainFrame.getContentPane()
                .add(rightScrollPane);

        // 中右部分的文本域
        detailTextArea = new JTextArea();
        detailTextArea.setEditable(false);
        rightScrollPane.setViewportView(detailTextArea);

        // 显示“请选择网络设备：”的textPane
        JTextPane textPane = new JTextPane();
        textPane.setForeground(Color.BLACK);
        textPane.setEnabled(false);
        textPane.setFont(new Font("幼圆", Font.BOLD | Font.ITALIC, 16));
        textPane.setEditable(false);
        textPane.setText(" \u8BF7\u9009\u62E9\u7F51\u7EDC\u8BBE\u5907\uFF1A");
        textPane.setBounds(0, 27, 169, 25);
        mainFrame.getContentPane()
                .add(textPane);

        // 网络设备的下拉列表
        JComboBox<String> comboBox = new JComboBox<>();
        comboBox.setBackground(new Color(255, 239, 213));
        comboBox.setBounds(194, 30, 357, 21);
        mainFrame.getContentPane()
                .add(comboBox);

        JButton buttonStart = new JButton();
        buttonStart.setText("开始抓包");
        buttonStart.setBounds(580, 30, 80, 22);
        buttonStart.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        buttonStart.setActionCommand(CMD_START);
        buttonStart.addActionListener(listener);
        mainFrame.getContentPane()
                .add(buttonStart);

        JButton buttonStop = new JButton();
        buttonStop.setText("停止抓包");
        buttonStop.setBounds(680, 30, 80, 22);
        buttonStop.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        buttonStop.setActionCommand(CMD_STOP);
        buttonStop.addActionListener(listener);
        mainFrame.getContentPane()
                .add(buttonStop);

        // 下拉列表的监听与事件
        comboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String net = (String) comboBox.getSelectedItem();
                ArrayList<PcapIf> alldevs = CaptureUtil.CaptureNet();
                int i = 0;
                // System.out.println(net);
                for (PcapIf device : alldevs) {
                    if (net.equals(device.getDescription())) {
                        CaptureUtil.number = i;
                        CaptureUtil.stopCapturePacket();
                    }
                    i++;
                }
            }
        });

        // 下拉列表添加网络设备
        ArrayList<PcapIf> alldevs = CaptureUtil.CaptureNet();
        for (PcapIf device : alldevs) {
            comboBox.addItem(device.getDescription());
        }

        // 下部分大的显示统计结果的面板，分下左部分的文字区域和下右部分的图形区域
        JPanel jp_showArea = new JPanel();
        jp_showArea.setBackground(new Color(175, 238, 238));
        jp_showArea.setBounds(0, 455, 869, 206);
        mainFrame.getContentPane()
                .add(jp_showArea);
        jp_showArea.setLayout(null);

        // 下左部分的文字区域，文字的方式显示统计结果
        JPanel jp_wordArea = new JPanel();
        jp_wordArea.setBounds(40, 10, 320, 186);
        jp_showArea.add(jp_wordArea);
        jp_wordArea.setLayout(null);

        // 文本域
        statisticsTextArea = new JTextArea();
        statisticsTextArea.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 15));
        statisticsTextArea.setEditable(false);
        statisticsTextArea.setBounds(0, 0, 339, 186);
        jp_wordArea.add(statisticsTextArea);

        // 下右部分的图形区域，图形的方式显示统计结果
        chartArea = new JPanel();
        chartArea.setBounds(374, 10, 485, 186);
        jp_showArea.add(chartArea);
        chartArea.setLayout(new BorderLayout(0, 0));

        // 下最左部分的“统计区”文字显示
        JLabel lblNewLabel = new JLabel("<html>统<br/>计<br/>区<br/></html>");
        lblNewLabel.setFont(new Font("宋体", Font.BOLD | Font.ITALIC, 20));
        lblNewLabel.setBounds(10, 10, 26, 186);
        jp_showArea.add(lblNewLabel);

    }
}
