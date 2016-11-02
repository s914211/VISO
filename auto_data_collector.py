#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import commands
import re
import time
import sys
import threading
from threading import Thread

def create_vm():
	checkVM = commands.getoutput("virsh list --all | grep cuckoo")
	if len(checkVM) == 0:
		print "Install vm..."
		commands.getoutput("virt-install -n cuckoo -r 2048 --os-type=windows --os-variant=win7 --disk cuckoo.img,device=disk,bus=ide --vnc --noautoconsole --import")
		time.sleep(180)
		commands.getoutput("python cuckoo/cuckoo.py")

	else:
		print "Turn on vm..."
		commands.getoutput("virsh start cuckoo")
		time.sleep(30)
		commands.getoutput("python cuckoo/cuckoo.py")

def data_collect(mal_path, output_path):

	path, dirs, files = os.walk(mal_path).next()

	for file_name in files:
		submitCommand = "sudo python cuckoo/utils/submit.py " + mal_path + str(file_name)
		print submitCommand
		submitResult = commands.getoutput(submitCommand)
		print submitResult
		time.sleep(5)

		# For Strace
		processIDCommand = "ps aux | grep name | grep cuckoo | grep -v grep | awk '{print $2}'"
		processID = commands.getoutput(processIDCommand)
		pattern = r'[a-zA-Z0-9]+'
		malLabel = re.search(pattern, file_name).group()
		straceCommand = "sudo strace -o " + output_path + str(malLabel) + ".txt -p " +  str(processID)
		print straceCommand
		commands.getoutput(straceCommand)

def get_mal_len(mal_path):

	path, dirs, files = os.walk(mal_path).next()
	return len(files)

if __name__ == '__main__':
	Thread(target = create_vm).start()
	time.sleep(60)
	Thread(target = data_collect, args=(sys.argv[1], sys.argv[2])).start()
	mal_len = get_mal_len(sys.argv[1])
	time.sleep(150 * int(mal_len))
	commands.getoutput("ps aux | grep python | awk '{print $2}' | xargs kill -9")
