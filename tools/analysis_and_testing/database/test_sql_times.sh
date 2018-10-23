#!/bin/bash

counter=1
count=0
while [ $counter -le 10 ]
do
	count=$(($counter * 1000))
	hping3 127.0.0.1 -c $count -p 80 -s 5555 --udp --rand-source -i u1
	time ./fwall_reader -P
	sleep 3s
	./fwall_reader -E -R
	((counter++))
done
echo All done
