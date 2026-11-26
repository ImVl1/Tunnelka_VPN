package app.tunnelka.vpn;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** Resolves original socket tuples on a JVM thread before SOCKS forwarding. */
final class AppRouter {
    private final PackageManager packages;
    private final ConnectivityManager connectivity;
    private final Map<Integer, Integer> routes = new HashMap<>();
    private final ParcelFileDescriptor[] sockets;

    AppRouter(Context context, JSONArray rules) throws JSONException, IOException {
        packages = context.getPackageManager();
        connectivity = context.getSystemService(ConnectivityManager.class);
        Map<Integer, String> targets = new HashMap<>();
        for (int index = 0; index < rules.length(); index++) {
            JSONObject rule = rules.getJSONObject(index);
            int uid = uid(rule.getString("app"));
            if (uid < 0) continue;
            if (uid == context.getApplicationInfo().uid)
                throw new IllegalArgumentException("Нельзя назначить правило самой Tunnelka");
            String server = rule.isNull("server") ? "" : rule.getString("server");
            String previous = targets.put(uid, server);
            if (previous != null && !server.equals(previous))
                throw new IllegalArgumentException("У приложений с общим UID должны совпадать правила");
            // Positive route numbers match authenticated users of the SOCKS inbound.
            routes.put(uid, server.isEmpty() ? -1 : index + 1);
        }
        sockets = ParcelFileDescriptor.createSocketPair();
        Thread worker = new Thread(this::serve, "Tunnelka-app-rules");
        worker.setDaemon(true);
        worker.start();
    }

    private int uid(String pkg) {
        try {
            return packages.getApplicationInfo(pkg, 0).uid;
        } catch (PackageManager.NameNotFoundException ignored) {
            return -1;
        }
    }

    boolean covers(String pkg) { return routes.containsKey(uid(pkg)); }
    int getFd() { return sockets[0].getFd(); }

    private static InetSocketAddress endpoint(byte[] packet, int offset, int port) throws IOException {
        byte[] address = Arrays.copyOfRange(packet, offset, offset + packet[1]);
        return new InetSocketAddress(InetAddress.getByAddress(address), port);
    }

    /** Android's system DNS daemon (netd) sends queries to TUN_DNS (198.18.0.2:53) under its own UID. */
    private static boolean isSystemDns(byte[] packet, int dstPort) {
        return packet[0] == OsConstants.IPPROTO_UDP
                && dstPort == 53
                && packet[1] == 4
                && (packet[22] & 255) == 198
                && (packet[23] & 255) == 18
                && packet[24] == 0
                && packet[25] == 2;
    }

    private void serve() {
        try (ParcelFileDescriptor peer = sockets[1]) {
            DataInputStream input = new DataInputStream(new FileInputStream(peer.getFileDescriptor()));
            DataOutputStream output = new DataOutputStream(new FileOutputStream(peer.getFileDescriptor()));
            byte[] packet = new byte[38];
            while (true) {
                input.readFully(packet);
                int srcPort = ((packet[2] & 255) << 8) | (packet[3] & 255);
                int dstPort = ((packet[4] & 255) << 8) | (packet[5] & 255);
                int owner = connectivity.getConnectionOwnerUid(packet[0],
                        endpoint(packet, 6, srcPort), endpoint(packet, 22, dstPort));
                int route = owner >= 0
                        ? routes.getOrDefault(owner, 0)
                        : (isSystemDns(packet, dstPort) ? 0 : -1);
                output.writeInt(route);
            }
        } catch (IOException | SecurityException ignored) {
            // Service shutdown or revoked VPN ownership. Closing the peer makes
            // pending and future lookups fail closed on the native side.
        }
    }

    void shutdown() {
        try {
            Os.shutdown(sockets[0].getFileDescriptor(), OsConstants.SHUT_RDWR);
        } catch (ErrnoException ignored) {
        }
    }

    void close() throws IOException { sockets[0].close(); }
}
