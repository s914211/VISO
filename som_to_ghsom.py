import sys

if __name__ == '__main__':

    count = 0

    print "$TYPE inputvec"
    print "$XDIM " + str(sys.argv[1])
    print "$YDIM 1"

    with open(sys.argv[2], 'r') as f:
        for lines in f:
            if count == 0:
                print "$VECDIM " + str(lines)
                count += 1
            else:
                if count > 1:
                    word = lines.replace('\n', '').split(', ')
                    word.insert(len(word), word[0])
                    word.pop(0)
                    str_word = ' '.join(word)
                    print str_word
                else:
                    count += 1
