#!/bin/bash

# $1 = mal_path $2 = mal_data_location $3 = syscall_times $4 = test_name

if [ ! -d "somtoolbox/output/" ]; then
    mkdir somtoolbox/output
fi

if [ ! -d "somtoolbox/output/$4" ]; then
    mkdir somtoolbox/output/$4
else
    echo You have the same project name! Change it and try again!
    exit
fi

python auto_data_collector.py $1 $2

python strace_serial_cuckoovm_clustering.py $2 $3 > temp1

python ok.py temp1 > temp2

rm temp1

`sed '/^$/d' temp2 > temp3`

rm temp2

all_line_num=`wc -l < temp3`

line_num=`expr $all_line_num - 2`

`sed '2q;d' temp3 > somtoolbox/$4_attr`

python som_to_ghsom.py $line_num temp3 > somtoolbox/$4.in

rm temp3

python create_prop_file.py $4.in $4 > somtoolbox/$4.prop

./somtoolbox/somtoolbox.sh GHSOM somtoolbox/$4.prop -h --skipDWM

gunzip -r somtoolbox/output/$4/

python get_ghsom_result.py somtoolbox/output/$4/ $4.unit somtoolbox/$4.in somtoolbox/$4_attr > $4_rules.txt

virsh shutdown cuckoo
