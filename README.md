 A process protector for all Windows 64-bit systems. It can protect specified processes from being debugged, having their memory read or written, and from injection or other malicious operations.
 
 The core of this project operates at the driver level, while the application layer allows the process to be protected by issuing the CPUID instruction (along with specific registers) to be added to the protected process list.
 
 Tested successfully on Windows 7, Windows 8, Windows 8.1, and Windows 10

 This version is compatible with various systems by automatically calculating offsets. The compiled driver for Windows 7 is provided; for other platforms, simply switch the target system in the WDK to generate the driver.

 Test result for windows7:
 https://youtu.be/t0NBGZCEvrU
