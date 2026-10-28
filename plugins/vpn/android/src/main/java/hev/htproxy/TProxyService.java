package hev.htproxy;

/**
 * Привязка к libhev-socks5-tunnel.so. Имена пакета, класса и методов должны
 * совпадать с теми, что регистрирует библиотека в JNI_OnLoad.
 */
public final class TProxyService {
    public static native boolean TProxyStartService(String configPath, int fd);
    public static native boolean TProxyStopService();
    public static native boolean TProxyIsRunning();
    public static native long[] TProxyGetStats();

    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private TProxyService() {}
}
