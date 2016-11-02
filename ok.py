import sys

def getdata():

    # with open('/home/tommy/strace_serial_1000_attr.txt', 'r') as f:
    with open(sys.argv[1], 'r') as f:

        for lines in f:

            withoutsign = lines.replace('[', '').replace(']', '').replace("'", '')

            print withoutsign

if __name__ == '__main__':
    getdata()

# sed '/^$/d' svm_virus_clean.txt >> svm_virus_ok
