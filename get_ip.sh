/sbin/ifconfig|sed -n '/inet addr/s/^[^:]*:\([0-9.]\{7,15\}\) .*/\1/p'|grep -v 10.0.0.1|grep -v 192.168.1.1 |grep -v 127.0.0.1
