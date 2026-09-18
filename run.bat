@echo off
echo Running SentinelStream SIEM...
cd sentinelstream\sentinelstream
java -jar target\sentinel-stream.jar
cd ..\..
