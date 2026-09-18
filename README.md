# SentinelStream: Enterprise SIEM Log Processor

## 📌 Problem Statement
Modern enterprises generate massive volumes of server telemetry, network traffic, and application logs. Detecting malicious activities—such as distributed brute-force attacks or rapid data exfiltration—in real-time is a critical challenge. Single-threaded or poorly structured log processors often fail under high throughput, leading to dropped alerts and delayed incident response. There is a critical need for a resilient, highly concurrent, and structured backend system that can ingest streams of data, analyze them on the fly, and persist the results reliably for security analysts.

## 🚀 About the Project
**SentinelStream** is an enterprise-grade Security Information and Event Management (SIEM) log processing engine. It is designed to simulate the backend mechanics of industry-standard security tools used by companies like CrowdStrike and Splunk. 

The application ingests raw mock-telemetry logs (e.g., Linux `auth.log` or web firewall logs) using fast I/O streams, processes these logs concurrently utilizing a multithreaded Producer-Consumer architecture, and applies polymorphic security rules to detect threats. Threat data is then persisted to a database using a hybrid approach: high-speed raw telemetry ingestion via pure JDBC, and complex forensic entity management using Java Persistence API (JPA/Hibernate).

## 🧠 Core Concepts Used (Syllabus Mapping)
This project comprehensively integrates all core Java concepts:

* **Java Flow Control & OOP (Basics to Advanced):** 
  * Utilizes `if...else`, `switch`, and loops for log parsing.
  * Implements **Inheritance & Polymorphism** through an abstract `SecurityRule` base class extended by specific detection algorithms (e.g., `BruteForceDetector`).
  * Employs the **Singleton Pattern** for database connection pooling.
  * Uses **Enums** for standardizing Threat Levels (e.g., `LOW`, `CRITICAL`) and **Java Reflection** to dynamically load custom threat detection rules at runtime.
* **Java Exception Handling:**
  * Defines custom exceptions (e.g., `MalformedTelemetryException`) with standard `try...catch...finally` blocks to ensure the pipeline never crashes on corrupt data streams.
  * Uses custom Annotations like `@CriticalAudit` for tagging sensitive rules.
* **Multithreading:**
  * Builds a robust Producer-Consumer architecture. Producers read from log files, while multiple Consumer threads analyze packets concurrently.
  * Implements careful **Thread Synchronization** and lifecycle management to prevent race conditions on shared memory buffers.
* **Collections Framework & I/O Streams:**
  * Replaces standard arrays with robust Collections like `ArrayList` for batching DB writes and `Stack` for tracking sequential login anomalies.
  * Utilizes advanced Byte and Character-oriented streams (`BufferedReader`, `FileInputStream`) for efficient, non-blocking large file reads.
* **Database Applications (JDBC & JPA):**
  * **JDBC:** Handles extremely fast, low-latency batch inserts of millions of raw telemetry rows.
  * **JPA/ORM:** Manages relational entities (`IncidentReport`, `ThreatOrigin`) allowing complex JPQL queries for incident triage and security reporting.

## ⚙️ Complete Procedural Guide (How to Build & Run)

### Prerequisites
* **Java Development Kit (JDK):** Version 11 or higher.
* **Database:** PostgreSQL or MySQL installed and running locally.
* **Build Tool:** Maven (or IDE built-in build tools like IntelliJ/Eclipse).

### Step 1: Database Setup
1. Open your SQL client.
2. Create a new database named `sentinel_stream_db`.
3. The JPA framework will automatically generate the schema based on the Entity classes, but you will need to execute the initial setup script (provided in the `sql/init.sql` folder) to create the raw JDBC telemetry table.

### Step 2: Configuration
1. Navigate to `src/main/resources/`.
2. Open `application.properties` (or `hibernate.cfg.xml`).
3. Update the database URL, username, and password to match your local database instance:
   ```properties
   db.url=jdbc:postgresql://localhost:5432/sentinel_stream_db
   db.user=postgres
   db.password=your_secure_password
   ```

### Step 3: Generating Mock Data
1. Run the `MockDataGenerator.java` utility script included in the `utils` package.
2. This will generate a 500MB `server_traffic.log` file in the root directory, simulating varying network requests, some of which contain embedded "attacks."

### Step 4: Building and Execution
1. Compile the project using your IDE or via terminal: `mvn clean install`.
2. Run the `Main.java` class. 
3. The console will display real-time thread spin-ups, logging the ingestion rate and flagging detected anomalies (e.g., `[CRITICAL] Brute Force Detected from IP: 192.168.1.45`).

### Step 5: Validating Results
1. Open your SQL client and query the database.
2. Run `SELECT * FROM incident_reports ORDER BY severity DESC;` to view the finalized, JPA-persisted threat analytics.
