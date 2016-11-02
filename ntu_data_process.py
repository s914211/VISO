import os
import re

def analyzeFile(file_path, file_name):

    malList = []

    with open(str(file_path) + "/" + str(file_name)) as data_file:

        for lines in data_file:
            pat = r'[A-Za-z0-9]+'
            match = re.findall(pat, lines)
            if len(match) == 9:
                malList.append(str(match[6]))
            else:
                pass

    return malList

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

    allSequenceList = []
    labelList = []

    path, dirs, files = os.walk("/home/tommy/project/calls").next()

    # Make the list with all sequence data

    for filename in files:

        # Save malware label in a list
        # pat = r'[a-z0-9]+\_[a-z0-9]+'
        pat = r'[a-z0-9]+\_[a-z0-9]+'
        match = re.search(pat, filename)
        malId = match.group()
        labelList.append(str(malId))

        # Get all malware's behavior list
        singleSequenceList = analyzeFile(path, filename)
        allSequenceList.append(singleSequenceList)

    # Remove the duplicate attribute and make the attribute vector

    allNonDuplicateList = []

    for i in range(0, len(allSequenceList)):
        nonDuplicateList = list(set(allSequenceList[i]))
        allNonDuplicateList.append(nonDuplicateList)

    allAttributeVector = getVector(allNonDuplicateList)

    vectorDimension = len(allAttributeVector)

    everyVectorList = [0] * vectorDimension

    print allAttributeVector

    # print len(allAttributeVector)

    #Parse data for SOM clustering

    # forSOMList = []
    #
    # apicallRange = 300
    #
    # for item in range(0, len(allSequenceList)):
    #     for apicall in range(0, len(allSequenceList[item])):
    #
    #         allCount = len(allSequenceList[item]) / apicallRange
    #
    #         if (allCount == 0):
    #             if (apicall == 0):
    #                 apiIndex = allAttributeVector.index(allSequenceList[item][apicall])
    #                 everyVectorList[apiIndex] += 1
    #             else:
    #                 if ((apicall % apicallRange) != 0):
    #                     apiIndex = allAttributeVector.index(allSequenceList[item][apicall])
    #                     everyVectorList[apiIndex] += 1
    #                 elif (apicall == (len(allSequenceList[item])-1)):
    #
    #                     everyVectorList.insert(0, labelList[item] + "_1")
    #                     print everyVectorList
    #                     forSOMList.append(everyVectorList)
    #                     everyVectorList = [0] * vectorDimension
    #         else:
    #             if (apicall == 0):
    #                 apiIndex = allAttributeVector.index(allSequenceList[item][apicall])
    #                 everyVectorList[apiIndex] += 1
    #             else:
    #                 if ((apicall % apicallRange) != 0):
    #                     apiIndex = allAttributeVector.index(allSequenceList[item][apicall])
    #                     everyVectorList[apiIndex] += 1
    #                 elif (apicall == (len(allSequenceList[item])-1)):
    #
    #                     everyVectorList.insert(0, labelList[item] + "_" + str(allCount + 1))
    #                     print everyVectorList
    #                     forSOMList.append(everyVectorList)
    #                     everyVectorList = [0] * vectorDimension
    #                 elif (apicall % apicallRange == 0):
    #                     count = apicall / apicallRange
    #
    #                     everyVectorList.insert(0, labelList[item] + "_" + str(count))
    #                     print everyVectorList
    #                     forSOMList.append(everyVectorList)
    #                     everyVectorList = [0] * vectorDimension
