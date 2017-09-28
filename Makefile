mptun : mptun.c
	gcc -o $@ $^ -g -Wall
	mipsel-openwrt-linux-gcc -EL -o $@.mips $^ -g -Wall
clean :
	rm mptun
