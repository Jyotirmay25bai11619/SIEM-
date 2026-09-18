@echo off
echo Building SentinelStream SIEM...
cd sentinelstream\sentinelstream
"C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2\plugins\maven\lib\maven3\bin\mvn.cmd" clean install
cd ..\..
echo Build complete!
