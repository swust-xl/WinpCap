package swust.winpcap;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.DecimalFormat;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 监听器
 * 
 */
public class Listener implements ActionListener {

    private static DecimalFormat df = new DecimalFormat("0.0000");
    private ScheduledThreadPoolExecutor executor = ScheduledThreadPoolExecutorFactory.getInstance()
            .defaultExecutor();

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd) {
        case MainWindow.CMD_START:
            MainWindow.listModel.setSize(1024);
            // 开启抓包线程
            executor.schedule(new Runnable() {
                @Override
                public void run() {
                    CaptureUtil.CapturePacket(CaptureUtil.CaptureNet(), new PcapHandler<>());
                }
            }, 0, TimeUnit.MILLISECONDS);
            // 处理数据包的数据并展示
            executor.schedule(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        if (!PacketHandler.packetQueue.isEmpty()) {
                            PacketHandler.getInstance()
                                    .handlePacket(PacketHandler.packetQueue.poll());
                        }
                    }
                }
            }, 0, TimeUnit.MILLISECONDS);
            // 实时刷新图表
            executor.scheduleAtFixedRate((new Runnable() {
                @Override
                public void run() {
                    new BarChart().showChart();
                }
            }), 0, 800, TimeUnit.MILLISECONDS);
            break;
        case MainWindow.CMD_STOP:
            CaptureUtil.stopCapturePacket();
            this.executor.shutdown();
            this.executor = ScheduledThreadPoolExecutorFactory.getInstance()
                    .defaultExecutor();
            MainWindow.statisticsTextArea.setText("");
            String message = new StringBuilder().append("Tcp:\t")
                    .append(PacketHandler.numberOfTcp)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfTcp))
                    .append("KB\n")
                    .append("Udp:\t")
                    .append(PacketHandler.numberOfUdp)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfUdp))
                    .append("KB\n")
                    .append("Icmp:\t")
                    .append(PacketHandler.numberOfIcmp)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfIcmp))
                    .append("KB\n")
                    .append("Arp:\t")
                    .append(PacketHandler.numberOfArp)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfArp))
                    .append("KB\n")
                    .append("广播包:\t")
                    .append(PacketHandler.numberOfWideSpread)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfSpread))
                    .append("KB\n")
                    .append("总流量:\t")
                    .append(PacketHandler.numberOfPacket)
                    .append("包\t")
                    .append(df.format(PacketHandler.totalOfIp))
                    .append("MB")
                    .toString();
            MainWindow.statisticsTextArea.append(message);
            break;
        case MainWindow.CMD_CLEAN:
            CaptureUtil.clearPacket();
            MainWindow.chartArea.removeAll();
            MainWindow.chartArea.repaint();
            break;
        case MainWindow.CMD_ANALYSE:
            PacketAnalyse.analyse();
            break;
        case MainWindow.CMD_SAVE:
            SaveFile sf = new SaveFile();
            StringBuilder stringBuilder = new StringBuilder();
            PacketHandler.map.forEach((k, v) -> {
                stringBuilder.append(k)
                        .append(":\r{")
                        .append(v)
                        .append("\r}\r");
            });
            sf.saveFile(MainWindow.mainFrame, stringBuilder.toString());
            break;
        case MainWindow.CMD_PAINT:
            new BarChart().showChart();
            break;
        default:
            break;
        }

    }
}
