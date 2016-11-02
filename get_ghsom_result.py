import re
import sys

def get_specific_vector(location, unit_file, input_file, feature_list):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)

    for groups in result_list:
        for group in groups:
            for feature in feature_list:
                if feature in group:
                    print groups
                    break

def get_all_clean_vector(location, unit_file, input_file):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)

    mal_label_save = []
    count = 1
    for groups in result_list:
        for group in groups:
            pat = r'[a-z0-9]+\_[a-z0-9]+'
            match = re.search(pat, group)
            malId = match.group()
            mal_label_save.append(malId)

        if mal_label_save.count(mal_label_save[0]) == len(mal_label_save):
            print str(count) + ":" + str(groups)
            mal_label_save = []
            count+=1
        else:
            mal_label_save = []

def get_all_without_benign_vector(location, unit_file, input_file):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)

    mal_label_save = []
    count = 1
    for groups in result_list:
        for group in groups:
            pat = r'[a-z0-9]+\_[a-z0-9]+'
            match = re.search(pat, group)
            malId = match.group()
            mal_label_save.append(malId)

        if "filezilla" not in mal_label_save and "chrome" not in mal_label_save:
            print str(count) + ":" + str(groups)
            mal_label_save = []
            count += 1
        else:
            mal_label_save = []

def get_all_result_vector(location, unit_file, input_file):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)
    print result_list

def get_all_clean_vector_rule(location, unit_file, input_file, attr_file):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)

    mal_label_save = []
    clean_groups = []
    clean_groups_labels = []
    count = 1
    for groups in result_list:
        for group in groups:
            pat = r'[a-z0-9]+\_[a-z0-9]+'
            match = re.search(pat, group)
            malId = match.group()
            mal_label_save.append(malId)

        if mal_label_save.count(mal_label_save[0]) == len(mal_label_save):
            clean_groups.append(groups)
            clean_groups_labels.append(mal_label_save[0])
            mal_label_save = []
            count+=1
        else:
            mal_label_save = []

    all_rule_list = [[] for x in xrange(len(clean_groups_labels))]
    rule_count = 0
    rule_list = []

    for groups in clean_groups:
        for group in groups:
            splits = str(group).replace('"', '').replace("'", '').split()

            for i in range(0, len(splits) - 1):
                if len(rule_list) < len(splits):
                    if i != (len(splits) - 1):
                        rule_list.append([])
                        rule_list[i].append(0)
                        rule_list[i].append(int(splits[i]))
                else:
                    if i != (len(splits) - 1):
                        if splits[i] > rule_list[i][1]:
                            rule_list[i][1] = int(splits[i])
                        else:
                            if splits[i] == 0:
                                rule_list[i][0] = int(splits[i])

        all_rule_list[rule_count].append(clean_groups_labels[rule_count])
        all_rule_list[rule_count].append(rule_list)
        rule_count += 1
        rule_list = []

    attr_list = []
    with open(attr_file) as f:
        for line in f:
            attr_list.append(line.replace('\n', '').split(', '))

    attr_list = attr_list[0]
    final_rule_list = []
    final_count = 0

    final_result = [[] for x in xrange(len(clean_groups_labels))]

    for rule in all_rule_list:
        rule_name = rule[0]
        final_rule_list.append(rule_name)
        for rules in rule[1]:
            if len(rules) == 2:
                if rules[1] != 0:
                    rule_index = rule[1].index(rules)
                    attr_name = attr_list[rule_index]
                    final_rule_list.append(str(attr_name) + ": " + str(rules[0]) + "~" + str(rules[1]))
        final_result[final_count].append(final_rule_list)
        final_count += 1
        final_rule_list = []

    for result in final_result:
        print result
        print ""

def get_all_without_benign_vector_rule(location, unit_file, input_file, attr_file):
    count = 0
    interval = [0, 0]
    url_judge = 0
    num_cluster = 0
    group_list = []
    all_list = []
    sub_file_list = []
    with open(location + unit_file) as f:
        for lines in f:
            if ("$NR_VEC_MAPPED") in lines:
                num_cluster = int(lines.split()[1])
                interval[0] = count + 2
                interval[1] = count + 2 + num_cluster
                url_judge = interval[1] + 2
            else:
                if (count != 0 and count >= interval[0] and count <= interval[1]):
                    if ("$") not in lines:
                        malware = lines.split('\n')
                        group_list.append(malware[0])
                else:
                    if (len(group_list) != 0):
                        all_list.append(group_list)
                        group_list = []
                    if (count == url_judge):
                        if ("$URL_MAPPED_SOMS") in lines:
                            all_list.pop()
                            submapped_file_name = lines.split()[1]
                            submapped_file_name = location + submapped_file_name + '.unit'
                            sub_file_list.append(submapped_file_name)
            count+=1
    while len(sub_file_list) != 0:
        for sub_file in sub_file_list:
            with open(sub_file) as f:
                for lines in f:
                    if ("$NR_VEC_MAPPED") in lines:
                        num_cluster = int(lines.split()[1])
                        interval[0] = count + 2
                        interval[1] = count + 2 + num_cluster
                        url_judge = interval[1] + 2
                    else:
                        if (count != 0 and count >= interval[0] and count <= interval[1]):
                            if ("$") not in lines:
                                malware = lines.split('\n')
                                group_list.append(malware[0])
                        else:
                            if (len(group_list) != 0):
                                all_list.append(group_list)
                                group_list = []
                            if (count == url_judge):
                                if ("$URL_MAPPED_SOMS") in lines:
                                    all_list.pop()
                                    submapped_file_name = lines.split()[1]
                                    submapped_file_name = location + submapped_file_name + '.unit'
                                    sub_file_list.append(submapped_file_name)
                    count+=1
            sub_file_list.remove(sub_file)
    result_list = [[] for x in xrange(len(all_list))]
    with open(input_file) as f:
        for lines in f:
            if len(lines) != 1:
                malware_name = lines.split()[-1]
                for i in range(0, len(all_list)):
                    if malware_name in all_list[i]:
                        vector = lines.split('\n')[0]
                        result_list[i].append(vector)

    mal_label_save = []
    clean_groups = []
    clean_groups_labels = []
    count = 1
    for groups in result_list:
        for group in groups:
            pat = r'[a-z0-9]+\_[a-z0-9]+'
            match = re.search(pat, group)
            malId = match.group()
            mal_label_save.append(malId)

        if not any('exe' in c for c in mal_label_save):
            clean_groups.append(groups)
            clean_groups_labels.append(mal_label_save)
            mal_label_save = []
            count += 1
        else:
            mal_label_save = []
        # if not any('filezilla' in f for f in mal_label_save):
        #     if not any('chrome' in c for c in mal_label_save):
        #         clean_groups.append(groups)
        #         clean_groups_labels.append(mal_label_save)
        #         mal_label_save = []
        #         count += 1
        # else:
        #     mal_label_save = []

    all_rule_list = [[] for x in xrange(len(clean_groups_labels))]
    rule_count = 0
    rule_list = []

    for groups in clean_groups:
        for group in groups:
            splits = str(group).replace('"', '').replace("'", '').split()

            for i in range(0, len(splits) - 1):
                if len(rule_list) < len(splits):
                    if i != (len(splits) - 1):
                        rule_list.append([])
                        rule_list[i].append(0)
                        rule_list[i].append(int(splits[i]))
                else:
                    if i != (len(splits) - 1):
                        if int(splits[i]) > int(rule_list[i][1]):
                            rule_list[i][1] = int(splits[i])
                        else:
                            if int(rule_list[i][0]) == 0:
                                rule_list[i][0] = int(splits[i])
                            else:
                                if int(splits[i]) < int(rule_list[i][0]):
                                    rule_list[i][0] = int(splits[i])

        all_rule_list[rule_count].append(clean_groups_labels[rule_count])
        all_rule_list[rule_count].append(rule_list)
        rule_count += 1
        rule_list = []

    attr_list = []
    with open(attr_file) as f:
        for line in f:
            attr_list.append(line.replace('\n', '').split(', '))

    attr_list = attr_list[0]
    final_rule_list = []
    final_count = 0

    final_result = [[] for x in xrange(len(clean_groups_labels))]

    for rule in all_rule_list:
        rule_name = rule[0]
        final_rule_list.append(rule_name)
        for rules in rule[1]:
            if len(rules) == 2:
                if rules[1] != 0:
                    rule_index = rule[1].index(rules)
                    attr_name = attr_list[rule_index]
                    if int(rules[0]) != int(rules[1]):
                        final_rule_list.append(str(attr_name) + ": " + str(rules[0]) + "~" + str(rules[1]))
                    else:
                        final_rule_list.append(str(attr_name) + ": " + str(rules[0]))
        no_identical_list = list(set(final_rule_list[0]))
        final_rule_list.pop(0)
        no_identical_rule = list(set(final_rule_list))
        no_identical_rule.insert(0, no_identical_list)
        final_result[final_count].append(no_identical_rule)
        # final_rule_list.insert(0, list(set(final_rule_list[0])))
        # final_rule_list.pop(1)
        # final_result[final_count].append(final_rule_list)
        final_count += 1
        final_rule_list = []

    for result in final_result:
        print result
        print ""

if __name__ == '__main__':
    # get_specific_vector('/home/tommy/ntu_30_5_4/', 'ntu.unit', '/home/tommy/ntu_30_5_4.in', ['60a92ad9b580573b636dfcc369755355_1444_10004'])
    # get_all_clean_vector('/home/tommy/strace_serial_1000/', 'strace_serial_1000.unit', '/home/tommy/strace_serial_1000.in')
    # get_all_result_vector('/home/tommy/ntu_30_5_1/', 'ntu.unit', '/home/tommy/ntu_30_5_1.in')
    # get_all_clean_vector_rule('/home/tommy/ntu_30_5_1/', 'ntu.unit', '/home/tommy/ntu_30_5_1.in', '/home/tommy/ntu_30_5_1_attr')
    # get_all_without_benign_vector('/home/tommy/strace_serial_1000/', 'strace_serial_1000.unit', '/home/tommy/strace_serial_1000.in')
    # get_all_without_benign_vector_rule('/home/tommy/ntu_30_5_1/', 'ntu.unit', '/home/tommy/ntu_30_5_1.in', '/home/tommy/ntu_30_5_1_attr')
    get_all_without_benign_vector_rule(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
