import sys

def getdata():

    with open(sys.argv[1], 'r') as f:

        for lines in f:

            withoutsign = lines.replace('[', '').replace(']', '').replace("'", '')

            print withoutsign

if __name__ == '__main__':
    getdata()
