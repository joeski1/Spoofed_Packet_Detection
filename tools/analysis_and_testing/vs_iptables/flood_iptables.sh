#!/bin/bash

hping3 127.0.0.1 -c 1 -p 80 --udp -a 69.69.69.27
hping3 127.0.0.1 -c 100000 -p 80 --udp --rand-source -i u1
hping3 127.0.0.1 -c 1 -p 80 --udp -a 69.69.69.28
