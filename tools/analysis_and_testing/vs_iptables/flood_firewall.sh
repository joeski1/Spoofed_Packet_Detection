#!/bin/bash

counter=96
while [ $counter -le 100 ]
do
	hping3 127.0.0.1 -c 10000 -p 80 -s 5555 --udp --rand-source -i u200
	sleep 1s
	./read_insertion_times insertion_times/one_tree_slow/output${counter}.txt
	((counter++))
done
echo All done
