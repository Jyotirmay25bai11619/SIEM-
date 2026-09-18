# SentinelStream: Enterprise SIEM Log Processor

## 📌 Problem Statement
Modern enterprises generate massive volumes of server telemetry, network traffic, and application logs. Detecting malicious activity — such as distributed brute-force login attacks or rapid data exfiltration — in real time is a critical challenge. Single-threaded or poorly structured log processors fail under high throughput, leading to dropped alerts and delayed incident response. There is a critical need for a resilient, highly concurrent, and structured backend system that can ingest streams of data, analyze them on the fly, and persist the results reliably for security analysts.

**How SentinelStream answers this:**
| Requirement from the problem statement | How the codebase satisfies it |
|---|---|
| Detect brute-force attacks in real time | `BruteForceDetector` fires the moment a sliding-window failure threshold is crossed, per source IP |
| Detect rapid data exfiltration | `DataExfiltrationDetector` watches for high-volume `DATA_TRANSFER`/`FILE_ACCESS` bursts in a short window |
| Resilient under high throughput | Bounded `SharedLogBuffer` (backpressure) + a fixed consumer thread pool prevent both memory blow-up and dropped input |
| Never drop alerts / crash on bad data | Every malformed line throws a checked `MalformedTelemetryException` that is caught and logged per-line — one bad record never kills the run |
| Persist results reliably | Hybrid persistence: raw JDBC batch inserts for throughput, JPA/Hibernate for relational incident modeling |

## 🚀 About the Project
**SentinelStream** is an enterprise-grade Security Information and Event Management (SIEM) log processing engine. It simulates the backend mechanics of industry-standard security tools used by companies like CrowdStrike and Splunk.

The application ingests raw mock-telemetry logs using fast I/O streams, processes them concurrently via a multithreaded Producer-Consumer architecture, and applies polymorphic security rules to detect threats. Threat data is persisted using a hybrid approach: high-speed raw telemetry ingestion via pure JDBC, and complex forensic entity management via JPA/Hibernate.

## 🏗️ Architecture

```
server_traffic.log
       │
       │  BufferedReader / FileInputStream (streamed, never fully loaded into memory)
       ▼
  LogProducer (1 thread)  ──parses lines, catches MalformedTelemetryException──►
       │
       ▼
  SharedLogBuffer (bounded BlockingQueue — provides backpressure)
       │
       ├──► LogConsumer thread #1 ─┐
       ├──► LogConsumer thread #2 ─┤  each owns its OWN SecurityRule instances
       ├──► LogConsumer thread #3 ─┤  (loaded via reflection, RuleLoader)
       └──► LogConsumer thread #N ─┘
                    │                              │
        every record, batched          every rule match (finding)
                    ▼                              ▼
      TelemetryBatchWriter (pure JDBC)     IncidentReportDAO (JPA/Hibernate)
      → raw_telemetry table                → incident_reports + threat_origins
      (millions of rows, write-once,       (few rows, richly queried,
       PreparedStatement batch insert)      relational, JPQL triage queries)
                    │                              │
                    └──────────► PostgreSQL ◄──────┘
```

## 🧠 Core Concepts Used (Syllabus Mapping)

| Concept | Where it lives |
|---|---|
| `if/else`, `switch`, loops | `LogParser` (event-type normalization), `MockDataGenerator` |
| Inheritance & Polymorphism | `SecurityRule` (abstract) ← `BruteForceDetector`, `DataExfiltrationDetector` |
| Singleton Pattern | `DatabaseConnectionManager` (double-checked locking, thread-safe) |
| Enums | `ThreatLevel` |
| Reflection | `RuleLoader` — instantiates rule classes by fully-qualified name at runtime |
| Custom checked exceptions | `MalformedTelemetryException`, used with `try/catch/finally` in `LogProducer` |
| Custom annotations | `@CriticalAudit`, read via reflection in `RuleLoader` |
| Multithreading / Producer-Consumer | `LogProducer`, `LogConsumer`, `SharedLogBuffer` (`BlockingQueue`) |
| Collections Framework | `ArrayList` (JDBC batching in `LogConsumer`), `Stack` (`BruteForceDetector`'s per-IP failure window) |
| I/O Streams | `BufferedReader` + `FileInputStream` + `InputStreamReader` in `LogProducer` |
| JDBC | `TelemetryBatchWriter` — raw batch inserts to `raw_telemetry` |
| JPA/Hibernate | `IncidentReport`, `ThreatOrigin` entities; `IncidentReportDAO` with JPQL queries |

## 📂 Project Structure
```
sentinelstream/
├── pom.xml
├── sql/init.sql                          # creates the raw_telemetry table
├── src/main/resources/
│   ├── application.properties            # DB connection + pipeline tuning
│   └── META-INF/persistence.xml          # JPA persistence unit
└── src/main/java/com/sentinelstream/
    ├── Main.java                         # wires the whole pipeline together
    ├── annotation/CriticalAudit.java
    ├── exception/MalformedTelemetryException.java
    ├── model/ThreatLevel.java, TelemetryRecord.java
    ├── util/LogParser.java, MockDataGenerator.java
    ├── rules/SecurityRule.java, BruteForceDetector.java, DataExfiltrationDetector.java, RuleLoader.java
    ├── concurrency/SharedLogBuffer.java, LogProducer.java, LogConsumer.java
    ├── config/DatabaseConnectionManager.java     # Singleton connection pool
    └── persistence/
        ├── jdbc/TelemetryBatchWriter.java
        └── jpa/IncidentReport.java, ThreatOrigin.java, IncidentReportDAO.java, JpaUtil.java
```

## ⚙️ Complete Procedural Guide (How to Build & Run)

### Prerequisites
* **JDK 11+**
* **PostgreSQL** running locally (any recent version)
* **Maven** (or your IDE's built-in build tools)

### Step 1: Database Setup
1. Open your SQL client (`psql`, DBeaver, etc.).
2. Run the first line of `sql/init.sql` to create the database: `CREATE DATABASE sentinel_stream_db;`
3. Connect to that database and run the rest of `sql/init.sql` to create the `raw_telemetry` table (the JDBC fast-path table — kept outside Hibernate's control on purpose).
4. `incident_reports` and `threat_origins` do **not** need to be created manually — Hibernate generates them automatically on first run (`hibernate.hbm2ddl.auto=update` in `persistence.xml`).

### Step 2: Configuration
Edit `src/main/resources/application.properties` **and** `src/main/resources/META-INF/persistence.xml` — both need matching credentials:
```properties
db.url=jdbc:postgresql://localhost:5432/sentinel_stream_db
db.user=postgres
db.password=your_secure_password
```

### Step 3: Generating Mock Data
You don't have to run this manually — if `server_traffic.log` isn't present, `Main` generates it automatically on startup (size controlled by `mockdata.target.size.mb` in `application.properties`).

To generate it standalone instead:
```bash
mvn compile exec:java -Dexec.mainClass="com.sentinelstream.util.MockDataGenerator" -Dexec.args="50 server_traffic.log"
```
This produces a log file with normal traffic plus embedded brute-force and exfiltration attack bursts from a small pool of attacker IPs (`192.168.1.4x`–`192.168.1.5x`), so the rule engine has real signal to catch.

### Step 4: Building and Execution
```bash
mvn clean install
java -jar target/sentinel-stream.jar
```
The console will show real-time thread activity: the producer's ingestion rate, each consumer thread's active rule count, and `[HIGH]`/`[CRITICAL]` log lines the moment a rule fires, e.g.:
```
WARNING: [HIGH] [HIGH] BruteForceDetector from 192.168.1.47 :: 5 failed login attempts within 2 minutes
```

### Step 5: Validating Results
```sql
-- Raw ingested telemetry (JDBC fast path)
SELECT COUNT(*) FROM raw_telemetry;

-- Finalized, JPA-persisted threat analytics, highest severity first
SELECT * FROM incident_reports ORDER BY severity DESC;

-- Every incident tied to a specific attacking IP, via the ThreatOrigin relationship
SELECT ir.* FROM incident_reports ir
JOIN threat_origins t ON ir.threat_origin_id = t.id
WHERE t.ip_address = '192.168.1.47';
```

## 🔧 Tuning
All in `application.properties`:
* `pipeline.consumer.threads` — number of parallel consumer threads (default 4)
* `pipeline.buffer.capacity` — bounded queue size between producer and consumers (default 10,000)
* `db.pool.size` — JDBC Singleton pool size for the raw telemetry fast path (default 8)

## 📝 Notes on Design Decisions
* **Why two persistence paths?** Raw telemetry is high-volume, write-once, and never queried row-by-row by a human — JDBC batch inserts skip ORM overhead entirely. Incidents are comparatively rare, get read/joined by analysts, and benefit from Hibernate's relationship management and JPQL.
* **Why a `Stack` for brute-force tracking instead of a `List`?** The detector only ever needs to reason about the most recent contiguous run of failures for an IP and evict the oldest entries once they age out of the window — a natural LIFO/window-eviction access pattern.
* **Why does each consumer thread own its own rule instances?** Rules are stateful (e.g., per-IP failure counters). Sharing instances across threads would require locking on every single `inspect()` call, which would serialize the very detection work multithreading exists to parallelize.
