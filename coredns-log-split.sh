#!/bin/bash

coredns_path=/home/gopath/src/github.com/coredns/coredns

log_date=`date -d yesterday +%Y%m%d%H%M%S`
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

do_split

#do_del_log() {
#    find logs -type f -cmin +7 | xargs rm -rf
#}

#if do_split ;then
#    do_del_log
#    echo "Logs created 7 days before have been cleaned up!"
#else
#    exit 2
#fi
