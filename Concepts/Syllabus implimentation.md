# SentinelStream: Architecture & Syllabus Mapping Guide

Welcome to the technical documentation for **SentinelStream**, an enterprise-grade Security Information and Event Management (SIEM) system. This document outlines how the core concepts from the **Programming in Java (CSE2006)** curriculum are actively applied to build a highly concurrent, resilient, and real-world software architecture.

---

## 1. Java Introduction & Flow Control (Unit 1)
In a high-throughput system, fundamental flow control is the backbone of the data ingestion pipeline.
* **Java Flow Control:** The system utilizes robust `while` loops to continuously poll streaming log files, alongside `for-each` loops to iterate through parsed data packets .
* **Conditional Logic:** Complex `if...else` blocks and `switch` statements are employed at the parser level to categorize incoming raw text strings based on protocol types (e.g., HTTP, TCP, UDP) and route them to appropriate processing queues .
* **Expressions & Blocks:** Clean scoping using Java blocks ensures memory is efficiently managed during the creation of millions of temporary string tokens during log splitting .

## 2. Java Object-Oriented Programming (Unit 2)
SentinelStream relies heavily on advanced OOP principles to maintain a scalable and modular codebase.
* **Inheritance & Polymorphism:** At the core of the detection engine is an `Abstract Class` named `SecurityRule` with abstract methods . Concrete classes like `BruteForceDetector` and `SqlInjectionDetector` inherit from it, demonstrating **Method Overriding** and **Polymorphism** by implementing their own specific detection logic .
* **Encapsulation & Modifiers:** Sensitive configuration data (like DB credentials) are strictly encapsulated using `private` access modifiers and exposed only via secure getter methods .
* **Advanced Class Types:** 
  * **Singleton:** The `DatabaseConnectionManager` is implemented as a Singleton class to prevent connection leaks and manage a single, thread-safe connection pool .
  * **Java enum Class:** Threat severities (e.g., `LOW`, `MEDIUM`, `CRITICAL`) are strongly typed using enums, utilizing `enum Constructor` and `enum String` features .
  * **Reflection:** The system uses **Java Reflection** to dynamically discover and load new `SecurityRule` classes at runtime without requiring a system reboot .

## 3. Java Exception Handling & Multithreading (Unit 3)
To process millions of logs per minute without crashing, the system requires robust concurrency and error resilience.
* **Multithreading:** SentinelStream uses a Producer-Consumer architecture. We demonstrate **Thread Creations** and manage the **Thread Life Cycle** by having "Producer" threads read I/O files while a pool of "Consumer" threads parses the data .
* **Synchronization:** To avoid race conditions when multiple threads write to the in-memory alert queue, the project employs **Java Synchronization methods** (using `synchronized` blocks and concurrent data structures) .
* **Exception Handling:** Parsing unpredictable raw network data guarantees errors. The system uses comprehensive `try...catch` blocks to catch parsing errors. It implements custom exceptions using `throw` and `throws`, and utilizes **catch Multiple Exceptions** to handle I/O failures and database disconnects gracefully . 
* **Java Annotations:** Custom annotations (e.g., `@CriticalAudit`) are used to tag specific detection rules for specialized auditing .

## 4. Java List & I/O Streams (Unit 4)
Efficient memory and file management are critical for a SIEM processing heavy log files.
* **Java I/O Streams:** The application replaces basic arrays with advanced **Character-oriented streams** (`BufferedReader` and `FileReader`) to read massive `auth.log` files line-by-line efficiently without loading the entire file into memory .
* **String Operations:** Advanced **String classes and methods** (e.g., `split()`, `substring()`, `matches()`) are heavily utilized to tokenize raw log strings into IP addresses, timestamps, and payload data .
* **Collections Framework:** 
  * **Java Array List:** Used to buffer processed telemetry objects before executing batch inserts into the database .
  * **Java Stack:** Employed in the `PathTraversalDetector` to track sequential directory traversal attempts (e.g., `../`) in web server logs .

## 5. Database Applications with JDBC & JPA (Unit 5)
SentinelStream uses a hybrid database approach to balance high-speed ingestion with complex data modeling.
* **Database Applications with JDBC:** To handle thousands of log inserts per second, the system connects to the database using a **JDBC driver** and submits batched SQL `INSERT` queries . This demonstrates defining the JDBC API layout and specifying driver information externally .
* **Java Persistence API (JPA):** For the complex incident response dashboard, the system utilizes **JPA architecture** and **ORM Components** . 
* **CRUD & Entities:** When a threat is detected, it is modeled as a JPA Entity (`IncidentReport`). We perform **CRUD operations** using advanced mappings to correlate threats with known malicious IP databases using the **Java Persistence Query language (JPQL)** .

---
*This project stands as a comprehensive, real-world application of the CSE2006 syllabus, proving an ability to design, implement, and evaluate a complex computer-based system to meet enterprise needs.*
