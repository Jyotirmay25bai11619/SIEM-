package com.sentinelstream.exception;

/**
 * Thrown when a raw telemetry line cannot be parsed into a TelemetryRecord.
 *
 * This is a CHECKED exception on purpose: log parsing happens on a hot path
 * fed by untrusted, frequently corrupt input (truncated lines, encoding
 * issues, partial writes from the producer). Callers are forced to decide,
 * line by line, whether to skip-and-continue or escalate -- the pipeline
 * must never crash because one line out of millions was malformed.
 */
public class MalformedTelemetryException extends Exception {

    private final String offendingLine;
    private final long lineNumber;

    public MalformedTelemetryException(String message, String offendingLine, long lineNumber) {
        super(message);
        this.offendingLine = offendingLine;
        this.lineNumber = lineNumber;
    }

    public MalformedTelemetryException(String message, String offendingLine, long lineNumber, Throwable cause) {
        super(message, cause);
        this.offendingLine = offendingLine;
        this.lineNumber = lineNumber;
    }

    public String getOffendingLine() {
        return offendingLine;
    }

    public long getLineNumber() {
        return lineNumber;
    }

    @Override
    public String getMessage() {
        return String.format("%s [line=%d, content=\"%s\"]", super.getMessage(), lineNumber, offendingLine);
    }
}
