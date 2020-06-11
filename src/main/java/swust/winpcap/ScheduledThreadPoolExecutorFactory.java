package swust.winpcap;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class ScheduledThreadPoolExecutorFactory implements ThreadFactory {

    @Override
    public Thread newThread(Runnable r) {
        Thread thread = new Thread(r, "ScheduledTask");
        return thread;
    }

    /**
     * default
     */
    public ScheduledThreadPoolExecutor defaultExecutor() {
        return new ScheduledThreadPoolExecutor(5, this);
    }

    public ScheduledThreadPoolExecutor newExecutor(int corePoolSize) {
        return newExecutor(corePoolSize, Integer.MAX_VALUE, false);
    }

    public ScheduledThreadPoolExecutor newExecutor(int corePoolSize, long keepAliveTime,
            boolean allowCoreThreadTimeOut) {
        final ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(Integer.MAX_VALUE, this);
        executor.setCorePoolSize(corePoolSize);
        executor.setKeepAliveTime(keepAliveTime, TimeUnit.SECONDS);
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        return executor;
    }

    /**
     * 工厂无需创建多个
     */
    private ScheduledThreadPoolExecutorFactory() {}

    private static class FactoryInstance {
        private static final ScheduledThreadPoolExecutorFactory INSTANCE = new ScheduledThreadPoolExecutorFactory();
    }

    public static ScheduledThreadPoolExecutorFactory getInstance() {
        return FactoryInstance.INSTANCE;
    }

}