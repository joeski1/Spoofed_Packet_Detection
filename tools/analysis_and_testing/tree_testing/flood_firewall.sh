#!/bin/bash

counter=1
while [ $counter -le 10 ]
do
	./fwall_reader
	hping3 127.0.0.1 -c 101000 -p 80 -s 5555 --udp --rand-source -i u1
	sleep 3s
	./fwall_reader -E
	((counter++))
done
echo All done
