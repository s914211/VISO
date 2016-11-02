import sys

# argv[1] = input_file_name argv[2] = test_name

print "workingDirectory=somtoolbox/"
print "outputDirectory=output/" + sys.argv[2] + "/"
print "namePrefix=" + sys.argv[2]
print "vectorFileName=" + sys.argv[1]
print "sparseData=yes"
print "isNormalized=false"
print "randomSeed=7"

print "xSize=2"
print "ySize=2"
print "learnRate=0.7"
print "numIterations=30030"
print "tau=0.07"
print "tau2=0.0035"
