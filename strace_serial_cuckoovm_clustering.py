#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys

def analyzeFile(mal_id):

    apicallList = []

    with open(sys.argv[1] + mal_id) as inputData:
        for line in inputData:
            pattern = r'[a-zA-Z0-9]+'
            malLabel = re.search(pattern, line).group()
            apicallList.append(malLabel)

    return apicallList

def getVector(lists):

    nonDuplicateList = []
    for item in lists[0]:
        nonDuplicateList.append(item)

    for i in range(1, len(lists)):

        for j in lists[i]:

            if j not in nonDuplicateList:

                nonDuplicateList.append(str(j))

    return nonDuplicateList

if __name__ == '__main__':

    labelList = []
    allapicallList = []

    path, dirs, files = os.walk(sys.argv[1]).next()
    for serialFile in files:
        pattern = r'[a-zA-Z0-9]+'
    	malLabel = re.search(pattern, serialFile).group()
        labelList.append(malLabel)
        singleapicallList = analyzeFile(serialFile)
        allapicallList.append(singleapicallList)

    allNonDuplicateList = []

    for i in range(0, len(allapicallList)):
        nonDuplicateList = list(set(allapicallList[i]))
        allNonDuplicateList.append(nonDuplicateList)

    allAttributeVector = getVector(allNonDuplicateList)

    vectorDimension = len(allAttributeVector)

    print len(allAttributeVector)
    print allAttributeVector

    everyVectorList = [0] * vectorDimension

    # apicallRange = 30
    apicallRange = int(sys.argv[2])

    for item in range(0, len(allapicallList)):
        for apicall in range(0, len(allapicallList[item])):

            allCount = len(allapicallList[item]) / apicallRange

            if (allCount == 0):
                if (apicall == 0):
                    apiIndex = allAttributeVector.index(allapicallList[item][apicall])
                    everyVectorList[apiIndex] += 1
                else:
                    if ((apicall % apicallRange) != 0):
                        apiIndex = allAttributeVector.index(allapicallList[item][apicall])
                        everyVectorList[apiIndex] += 1
                    elif (apicall == (len(allapicallList[item])-1)):

                        everyVectorList.insert(0, labelList[item] + "_1")
                        print everyVectorList
                        everyVectorList = [0] * vectorDimension
            else:
                if (apicall == 0):
                    apiIndex = allAttributeVector.index(allapicallList[item][apicall])
                    everyVectorList[apiIndex] += 1
                else:
                    if ((apicall % apicallRange) != 0):
                        apiIndex = allAttributeVector.index(allapicallList[item][apicall])
                        everyVectorList[apiIndex] += 1
                    elif (apicall == (len(allapicallList[item])-1)):

                        everyVectorList.insert(0, labelList[item] + "_" + str(allCount + 1))
                        print everyVectorList
                        everyVectorList = [0] * vectorDimension
                    elif (apicall % apicallRange == 0):
                        count = apicall / apicallRange

                        everyVectorList.insert(0, labelList[item] + "_" + str(count))
                        print everyVectorList
                        everyVectorList = [0] * vectorDimension
