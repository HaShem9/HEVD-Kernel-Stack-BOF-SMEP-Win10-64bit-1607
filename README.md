# HEVD-Kernel-Stack-BOF-SMEP-1607
A Windows Kernel LPE exploit for HEVD targeting the Stack Overflow vulnerability on 1607 (RS1)

This exploit targest the classic stack buffer overflow vulnerability in the HEVD.sys driver, this exploit was written on Windows 10 64-bit 1607 so a SMEP (Supervisor Mode Execution Prevention) bypass is needed. This exploit builds a ROP chain to move the correct bits to disable SMEP into the CR4 (Control Register 4) Intel register. 

![image](https://user-images.githubusercontent.com/54753063/127082089-b4d89d78-8990-4688-b3fc-532fb70a2a5e.png)
