from pwn import *
import subprocess
import sys
import time
import re

def disas(a):
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    command = 'gdb -ex "disas main" {} > output.txt'.format(a)
    for i in range(1):
        pi = subprocess.Popen(command, shell=True)

def makeFrame(mainfuncFile):
    a = None
    subrsp_list = []
    cny_found = None

    matches = re.finditer(r'(0x[0-9a-f]+).*pushrbp', mainfuncFile, re.IGNORECASE)
    matches2 = re.finditer(r'subrsp.+(0x[0-9a-f]+)', mainfuncFile, re.IGNORECASE)
    matches3 = re.finditer(r'__stack_chk_fail@plt', mainfuncFile, re.IGNORECASE)
    for match in matches:
        if match:
            a = match.group(1)
    for match2 in matches2:
        if match2:
            subrsp_list.append((match2.group(0), match2.group(1)))
    for match3 in matches3:
        if match3:
            cny_found = True
    return a, subrsp_list , cny_found

print("[*] Please same directory ELF & StackVisual file")
a = input("[*] process : ").strip('\n')

disas(a)

with open("output.txt",'r') as f:
    mainfuncFile = f.read().replace(" ",'')

x,subrsp_list,cry_found = makeFrame(mainfuncFile)

print("*"*30)
print("RET <-- [rbp + 0x8]")
print("*"*30)
print("SFP <-- [rbp here]")
print("*"*30)
if cry_found == True:
    print("CANARY <-- [rbp - 0x8]")
    print("*"*30)
else:
    pass
for i, subrsp in enumerate(subrsp_list):
    print("var_{} <--[rbp - {}]".format(i+1, subrsp[1]))
    print("*"*30)