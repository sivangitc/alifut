import subprocess
import time
import ctypes

CREATE_SUSPENDED = 0x00000004

proc = subprocess.Popen(["C:\Windows\System32\calc.exe"], creationflags=CREATE_SUSPENDED)
time.sleep(20)