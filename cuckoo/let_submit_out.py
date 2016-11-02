import commands

while True:
    command = "python cuckoo.py"
    commands.getoutput(command)
    time.sleep(5)
    serial.write('\x03')
