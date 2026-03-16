package com.hoddmimes.ice.server;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Server-wide rolling 24-hour statistics. Singleton, thread-safe.
 * Counters reset on server restart (in-memory only).
 */
public class ServerStats {

    private static final ServerStats INSTANCE = new ServerStats();
    private static final long WINDOW_MS = 24L * 60 * 60 * 1000;

    private final ConcurrentLinkedQueue<Long> mLoginTimestamps        = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<Long> mMailReceivedTimestamps = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<Long> mMailSentTimestamps     = new ConcurrentLinkedQueue<>();

    private ServerStats() {}

    public static ServerStats getInstance() { return INSTANCE; }

    public void recordLogin()        { mLoginTimestamps.add(System.currentTimeMillis()); }
    public void recordMailReceived() { mMailReceivedTimestamps.add(System.currentTimeMillis()); }
    public void recordMailSent()     { mMailSentTimestamps.add(System.currentTimeMillis()); }

    public long loginsLast24h()       { return countLast24h(mLoginTimestamps); }
    public long mailReceivedLast24h() { return countLast24h(mMailReceivedTimestamps); }
    public long mailSentLast24h()     { return countLast24h(mMailSentTimestamps); }

    /** Evict expired entries from the queue head, then return current size. */
    private long countLast24h(ConcurrentLinkedQueue<Long> queue) {
        long cutoff = System.currentTimeMillis() - WINDOW_MS;
        Long head;
        while ((head = queue.peek()) != null && head < cutoff) {
            queue.poll();
        }
        return queue.size();
    }
}
