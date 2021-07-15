#!/bin/bash

coredns_path=$(cd "$(dirname "$0")"; pwd)

log_date=`date -d yesterday +%Y%m%d`
echo $log_date

do_split () {
    [ ! -d ${coredns_path}/logs ] && mkdir -p ${coredns_path}/logs
    source_file=${coredns_path}/coredns.log
    dest_file=${coredns_path}/logs/${log_date}.log
    cp $source_file $dest_file
    cat /dev/null > $source_file
    if [ $? -eq 0 ];then
        echo "Daily split is finished!"
    else
        echo "Daily Split is Failed!"
        exit 1
    fi
}

do_split_doh () {
    [ ! -d ${coredns_path}/logs ] && mkdir -p ${coredns_path}/logs
    source_file=${coredns_path}/coredns_doh.log
    dest_file=${coredns_path}/logs/${log_date}_doh.log
    cp $source_file $dest_file
    cat /dev/null > $source_file
    if [ $? -eq 0 ];then
        echo "DoH daily split is finished!"
    else
        echo "DoH daily Split is Failed!"
        exit 1
    fi
}

do_split_dot () {
    [ ! -d ${coredns_path}/logs ] && mkdir -p ${coredns_path}/logs
    source_file=${coredns_path}/coredns_dot.log
    dest_file=${coredns_path}/logs/${log_date}_dot.log
    cp $source_file $dest_file
    cat /dev/null > $source_file
    if [ $? -eq 0 ];then
        echo "DoT daily split is finished!"
    else
        echo "DoT daily Split is Failed!"
        exit 1
    fi
}

do_split
do_split_doh
do_split_dot

#do_del_log() {
#    find logs -type f -cmin +7 | xargs rm -rf
#}

#if do_split ;then
#    do_del_log
#    echo "Logs created 7 days before have been cleaned up!"
#else
#    exit 2
#fi
