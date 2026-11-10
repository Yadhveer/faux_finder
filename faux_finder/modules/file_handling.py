import os
import subprocess


def find_plist(directory):
    subdir = subdirectories(directory)
    plist_list = []
    for a in subdir:
            for i in a[2]:
                hex = hexdump(str(a[0]) + "/" + str(i))
                if b"62 70 6c 69 73 74 30 30" in hex:
                     plist_list.append(str(a[0]) + "/" + str(i))
                else:
                     continue
                    

    return plist_list



def subdirectories(path):
    list = os.walk(path)
    return list

def hexdump(file):
    temp = subprocess.Popen(['hexdump', '-C', '-n', '8', file], stdout = subprocess.PIPE)
    hex = temp.communicate()[0]
    return hex