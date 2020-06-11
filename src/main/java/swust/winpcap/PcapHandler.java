package swust.winpcap;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * 
 * 实现了PcapPacketHandler的接口，重写nextPacket方法
 * handler：一个处理，监听，回调的接口，用于在一个新的packet捕获的时候，获得通知
 * 
 */
public class PcapHandler<T> implements PcapPacketHandler<T> {

    @Override
    public void nextPacket(PcapPacket packet, T user) {
        // 对数据包的处理
        PacketHandler.getInstance()
                .savePacket(packet);
    }

}
