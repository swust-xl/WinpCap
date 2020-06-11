package swust.winpcap;

import java.awt.BorderLayout;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;

/**
 * 生成柱状图的类
 * 
 */
public class BarChart {

    private static JFreeChart creatChart(CategoryDataset dataset) {
        return ChartFactory.createBarChart("数据包统计结果", "数据包类型", "数量", dataset, PlotOrientation.HORIZONTAL, true, true,
                false);
    }

    /**
     * 数据集
     * 
     * @return dataset
     */
    public static CategoryDataset createDataset() {
        final String tcp = "TCP";
        final String udp = "UDP";
        final String arp = "ARP";
        final String icmp = "ICMP";
        final String widespread = "广播包";
        final String number = "包数量";
        final DefaultCategoryDataset dataset = new DefaultCategoryDataset();

        dataset.addValue(PacketHandler.numberOfTcp, tcp, number);
        dataset.addValue(PacketHandler.numberOfUdp, udp, number);
        dataset.addValue(PacketHandler.numberOfArp, arp, number);
        dataset.addValue(PacketHandler.numberOfIcmp, icmp, number);
        dataset.addValue(PacketHandler.numberOfWideSpread, widespread, number);

        return dataset;
    }

    /**
     * 显示图表
     */
    public void showChart() {
        MainWindow.chartArea.removeAll();
        ChartPanel chartPanel = new ChartPanel(creatChart(createDataset()));
        MainWindow.chartArea.setLayout(new BorderLayout()); // border布局
        MainWindow.chartArea.add(chartPanel, BorderLayout.CENTER);
        MainWindow.chartArea.validate(); // 设置为生效
    }
}
