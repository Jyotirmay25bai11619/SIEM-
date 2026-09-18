package com.sentinelstream.concurrency;

import com.sentinelstream.model.TelemetryRecord;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Thread-safe bounded buffer shared between the single producer thread and
 * the pool of consumer threads.
 *
 * Wraps a {@link LinkedBlockingQueue} rather than exposing it directly so
 * that:
 *   - capacity is fixed at construction (backpressure: a slow consumer
 *     pool naturally blocks a fast producer instead of causing unbounded
 *     memory growth on high-throughput log files);
 *   - a sentinel "poison pill" protocol is centralized here for clean
 *     shutdown once the producer has read the entire file.
 *
 * BlockingQueue's put()/take() already handle all the wait/notify style
 * synchronization internally, which is the correct, modern alternative to
 * hand-rolled wait()/notify() on a raw ArrayList for this kind of
 * producer-consumer hand-off.
 */
public class SharedLogBuffer {

    /** Sentinel record placed on the queue once per consumer to signal shutdown. */
    public static final TelemetryRecord POISON_PILL =
            new TelemetryRecord(-1, null, "0.0.0.0", "SHUTDOWN", "__POISON_PILL__");

    private final BlockingQueue<TelemetryRecord> queue;

    public SharedLogBuffer(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    /** Blocks if the buffer is full -- this is the backpressure mechanism. */
    public void put(TelemetryRecord record) throws InterruptedException {
        queue.put(record);
    }

    /** Blocks if the buffer is empty. */
    public TelemetryRecord take() throws InterruptedException {
        return queue.take();
    }

    public int size() {
        return queue.size();
    }
}
