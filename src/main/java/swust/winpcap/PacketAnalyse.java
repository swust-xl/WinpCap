package swust.winpcap;

import java.util.ArrayList;

import javax.swing.JOptionPane;

/**
 * 结果分析
 * 
 */
public class PacketAnalyse {

    private static StringBuilder stringBuilder;
    private static ArrayList<Integer> list;

    public static void analyse() {
        stringBuilder = new StringBuilder();
        list = new ArrayList<>();
        PacketHandler.map.forEach((k, v) -> {
            if (isContentContainsKeyword(v)) {
                list.add(k);
            }
        });
        if (list.isEmpty()) {
            stringBuilder.append("没有发现关键词");
        } else {
            stringBuilder.append("第")
                    .append(list.toString())
                    .append("项发现关键词");
        }
        JOptionPane.showMessageDialog(MainWindow.mainFrame, stringBuilder.toString(), "结果分析",
                JOptionPane.WARNING_MESSAGE);
    }

    private static boolean isContentContainsKeyword(String content) {
        if (content.contains("username") || content.contains("password") || content.contains("session")
                || content.contains("cookie")) {// TODO
            return true;
        }
        return false;
    }

}
