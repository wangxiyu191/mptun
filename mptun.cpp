#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cassert>
#include <sys/socket.h>
#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/uio.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#define IFNAMSIZ 16
#endif
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <netdb.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdarg>
#include <signal.h>
#include <inttypes.h>
#include <ctime>
#include <vector>

#if defined(IFF_TUN)
#define tun_read(...) read(__VA_ARGS__)
#define tun_write(...) write(__VA_ARGS__)
#elif defined(__APPLE__)
#define tun_read(...) utun_read(__VA_ARGS__)
#define tun_write(...) utun_write(__VA_ARGS__)
#endif

#define MAX_ADDRESS 26
#define BASE_COUNT 64
#define MAX_COUNT 16384
/* buffer for reading , must be >= 1500 */
#define BUFF_SIZE 2000
#define IP_SIZE 128
/* 1 hour time diff */
#define TIME_DIFF 3600

// todo: support ipv6
typedef struct sockaddr_in SOCKADDR;
typedef struct in_addr INADDR;

static int SIG = 0;

struct tundev {
	uint64_t key;
	time_t ti;
	int port;
	int tunfd;
	int remote_n;
	int local_n;
	SOCKADDR remote[MAX_ADDRESS];
	INADDR local[MAX_ADDRESS];
	int localfd[MAX_ADDRESS];
	int remote_count[MAX_ADDRESS];
	int local_count[MAX_ADDRESS];
	uint64_t in[MAX_ADDRESS];
	uint64_t out[MAX_ADDRESS];
	uint64_t drop;
	uint64_t untrack;
	uint64_t invalid;
};

static uint64_t
hash_key(const char * str, int sz) {
	uint32_t djb_hash = 5381L;
	uint32_t js_hash = 1315423911L;

	int i;
	for (i=0;i<sz;i++) {
		uint8_t c = (uint8_t)str[i];
		djb_hash += (djb_hash << 5) + c;
		js_hash ^= ((js_hash << 5) + c + (js_hash >> 2));
	}

	return (uint64_t) djb_hash << 32 | js_hash;
}

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static inline int
mptun_encrypt(const char in[BUFF_SIZE], int sz, char out[BUFF_SIZE], uint64_t key, time_t ti) {
	memcpy(out, in, sz);
	return sz;
}

static inline int
mptun_decrypt(const char in[BUFF_SIZE], int sz, char out[BUFF_SIZE], uint64_t key, time_t ti) {
	memcpy(out, in, sz);
	return sz;
}

static void
dumpinfo(struct tundev *tdev) {
	char tmp[1024];
	int i;
	uint64_t s = 0;
	for (i=0;i<tdev->remote_n;i++) {
		s += tdev->out[i];
		inet_ntop(AF_INET, &tdev->remote[i].sin_addr, tmp, sizeof(tmp));
		printf("-> %s %" PRId64 "\n", tmp, tdev->out[i]);
	}
	printf("Total out %" PRId64 "\n", s);
	printf("Drop out %" PRId64 "\n", tdev->drop);
	s = 0;
	for (i=0;i<tdev->remote_n;i++) {
		s += tdev->in[i];
		inet_ntop(AF_INET, &tdev->remote[i].sin_addr, tmp, sizeof(tmp));
		printf("<- %s %" PRId64 "\n", tmp, tdev->in[i]);
	}
	printf("Total in %" PRId64 "\n", s);
	printf("Untrack in %" PRId64 "\n", tdev->untrack);
	printf("Invalid in %" PRId64 "\n", tdev->invalid);
}

static void
dumpinfo_hup(struct tundev *tdev) {
	if (SIG) {
		dumpinfo(tdev);
		SIG = 0;
	}
}

#if defined(IFF_TUN)
static int
tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}
#elif defined(__APPLE__)
static int utun_open_helper (struct ctl_info ctlInfo, int utunnum)
{
	struct sockaddr_ctl sc;
	int fd;

	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

	if (fd < 0)
	{
		return -2;
	}

	if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
	{
		close (fd);
		return -2;
	}


	sc.sc_id = ctlInfo.ctl_id;
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;

	sc.sc_unit = utunnum+1;

	/* If the connect is successful, a utun%d device will be created, where "%d"
	 * is (sc.sc_unit - 1) */

	if (connect (fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
	{
		close(fd);
		return -1;
	}

	return fd;
}

static int
tun_alloc (char *dev)
{
	struct ctl_info ctlInfo;
	int fd;
	char utunname[20];
	int utunnum =-1;
	socklen_t utunname_len = sizeof(utunname);

	if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
		sizeof(ctlInfo.ctl_name))
	{
		printf("Opening utun: UTUN_CONTROL_NAME too long\n");
		return -1;
	}

	/* try to open first available utun device if no specific utun is requested */
	if (utunnum == -1)
	{
		for (utunnum=0; utunnum<255; utunnum++)
		{
			fd = utun_open_helper (ctlInfo, utunnum);
			 /* Break if the fd is valid,
			  * or if early initalization failed (-2) */
			if (fd !=-1)
				break;
		}
	}
	else
	{
		fd = utun_open_helper (ctlInfo, utunnum);
	}

	if(fd < 0) {
		printf("failed to create fd\n");
		return fd; //error
	}

	/* Retrieve the assigned interface name. */
	if (getsockopt (fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len)) {
		printf("Error retrieving utun interface name\n");
		return -1;
	}

	printf("Opened utun device %s\n", utunname);
	strcpy(dev, utunname); //return device name
	return fd;
}

//remove the IP version header from the result of bytes read or written.
static inline ssize_t header_modify_read_write_return (ssize_t len)
{
    if (len > 0)
        return len > (ssize_t) sizeof(u_int32_t) ? len - sizeof(u_int32_t) : 0;
    else
        return len;
}

//read from utun
static inline ssize_t
utun_read(int fd, char *buf, int len) {
	u_int32_t type;
	struct iovec iv[2];
	struct ip *iph;
	
	iph = (struct ip *) buf;

	if(iph->ip_v == 6)
		type = htonl(AF_INET6);
	else
		type = htonl(AF_INET);

	iv[0].iov_base = (char *)&type;
	iv[0].iov_len = sizeof (type);
	iv[1].iov_base = buf;
	iv[1].iov_len = len;

	return header_modify_read_write_return(readv(fd, iv, 2));
}
//write to utun
static inline ssize_t
utun_write(int fd, char *buf, int len)
{
	u_int32_t type;
	struct iovec iv[2];
	struct ip *iph;

	iph = (struct ip *) buf;

	if(iph->ip_v == 6)
		type = htonl(AF_INET6);
	else
		type = htonl(AF_INET);

	iv[0].iov_base = (char *)&type;
	iv[0].iov_len  = sizeof (type);
	iv[1].iov_base = buf;
	iv[1].iov_len  = len;

	return header_modify_read_write_return(writev(fd, iv, 2));
}
#endif

static int
inet_bind(INADDR *addr, int port) {
	int reuse = 1;
	SOCKADDR address;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return fd;
	}
	address.sin_family = AF_INET;
	address.sin_addr = *addr;
	address.sin_port = htons(port);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int)) ==-1) {
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	return fd;
}

static void
usage(void) {
	fprintf(stderr,
		"Usage:\n"
		"\t-i <ifacename>: Name of interface to use (for example: tun0). Final interface name may change on OSX\n"
		"\t-v <vpnlocalIP> : specify vpn address (for example: 10.0.0.1)\n"
		"\t-t <vpnremoteIP> : specify vpn P-t-P address (for example: 10.0.0.2)\n"
		"\t-r <remoteIP> : specify remote address, it can specify multi times. (or zero, if you run as server)\n"
		"\t-l <localIP> : specify local address, it can specify multi times. (or zero, if you run as server)\n"
		"\t-p <port> : specify port for tunnel\n"
		"\t-k <key> : optional password\n"
	);
	exit(1);
}

static void
add_remote(struct tundev *tdev, SOCKADDR *addr, int bytes) {
	int i;
	int mincount = MAX_COUNT;
	int minidx = -1;
	for (i=0;i<tdev->remote_n;i++) {
		if (memcmp(&addr->sin_addr, &tdev->remote[i].sin_addr, sizeof(INADDR))==0) {
			tdev->remote[i].sin_port = addr->sin_port;	// update port (NAT may change port)
			if (++tdev->remote_count[i] > MAX_COUNT) {
				int j;
				for (j=0;j<tdev->remote_n;j++) {
					tdev->remote_count[j] /= 2;
				}
			}
			tdev->in[i] += bytes;
			return;
		} else if (tdev->remote_count[i] < mincount) {
			mincount = tdev->remote_count[i];
			minidx = i;
		}
	}
	if (tdev->remote_n < MAX_ADDRESS) {
		i = tdev->remote_n++;
	} else {
		i = minidx;
	}
	tdev->remote[i] = *addr;
	tdev->remote_count[i] = 0;
	tdev->untrack += tdev->in[i];
	tdev->in[i] = bytes;
}

// forward ip packet from internet to tun , and return peer address 
static void
inet_to_tun(struct tundev *tdev, int index) {
	SOCKADDR sa;
	int inetfd = tdev->localfd[index];
	int tunfd = tdev->tunfd; 
	char buf[BUFF_SIZE], outbuff[BUFF_SIZE];
	ssize_t n, rn;
	for (;;) {
		socklen_t addrlen = sizeof(sa);
		n = recvfrom(inetfd, buf, BUFF_SIZE, 0,(struct sockaddr *)&sa, &addrlen);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("recvfrom");
				exit(1);
				// fail
			}
		} else {
			break;
		}
	}
	rn = n;
	if (rn < 0) {
		tdev->invalid += n;
		return;
	}

	for (;;) {
		int ret = tun_write(tunfd, buf, rn);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("write tun");
				exit(1);
			}
		} else {
			break;
		}
	}

	// succ
	add_remote(tdev, &sa, (int)n);
}

static void
drop_tun(struct tundev *tdev) {
	int tunfd = tdev->tunfd;
	char buf[BUFF_SIZE];
	ssize_t n;
	for (;;) {
		n = tun_read(tunfd, buf, BUFF_SIZE);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("drop");
				exit(1);
				return;
			}
		} else {
			break;
		}
	}
	tdev->drop += n;
}

static int
choose_local(struct tundev *tdev, fd_set *set) {
	int i;
	int t = 0;
	int r;
	if (tdev->local_n == 1) {
		return 0;
	}
	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], set)) {
			t += BASE_COUNT + tdev->local_count[i];
		}
	}
	if (t == 0)
		return 0;
	r = random() % t;
	t = 0;
	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], set)) {
			t += BASE_COUNT + tdev->local_count[i];
			if (r < t) {
				return i;
			}
		}
	}
	return 0;
}

static int
choose_remote(struct tundev *tdev) {
	return (random())%(tdev->remote_n);
}

// forward ip packet from tun to internet with address
static void
tun_to_inet(struct tundev *tdev, fd_set *wt) {
	int tunfd = tdev->tunfd;
	int localindex = choose_local(tdev, wt);
	int inetfd = tdev->localfd[localindex];
	int remoteindex = choose_remote(tdev);
	SOCKADDR * addr = &tdev->remote[remoteindex];
	char buf[BUFF_SIZE], outbuf[BUFF_SIZE];
	ssize_t n;
	for (;;) {
		n = tun_read(tunfd, buf, BUFF_SIZE);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("read tun");
				exit(1);
				return;
			}
		} else {
			break;
		}
	}

	if (n < 0) {
		fprintf(stderr, "Invalid tun package size %d", (int)n);
		return;
	}

	for (;;) {
		int ret = sendto(inetfd, buf, n, 0, (struct sockaddr *)addr, sizeof(SOCKADDR));
		if (ret < 0 && errno == EINTR) {
			continue;
		} else {
			break;
		}
	}
	//dumpinfo(tdev);
	tdev->out[remoteindex] += n;
}

static void
forwarding(struct tundev *tdev, int maxrd, fd_set *rdset, int maxwt, fd_set *wtset) {
	int i;
	fd_set rd,wt;

	// read
	rd = *rdset;
	for (;;) {
		int ret = select(maxrd, &rd, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR) {
				dumpinfo_hup(tdev);
				continue;
			}
			perror("select read");
			exit(1);
		} else {
			break;
		}
	}

	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], &rd)) {
			// forward ip packet of inet to tun
			if (++tdev->local_count[i] > MAX_COUNT) {
				int j;
				for (j=0;j<tdev->local_n;j++) {
					tdev->local_count[j] /= 2;
				}
			}
			inet_to_tun(tdev, i);
		}
	}

	if (FD_ISSET(tdev->tunfd, &rd)) {
		// forward ip packet of tun to inet
		wt = *wtset;
		for (;;) {
			int ret = select(maxwt, NULL, &wt, NULL, NULL);
			if (ret < 0) {
				if (errno == EINTR) {
					dumpinfo_hup(tdev);
					continue;
				}
				perror("select write");
				exit(1);
			} else {
				break;
			}
		}
		if (tdev->remote_n == 0) {
			drop_tun(tdev);
		} else {
			tun_to_inet(tdev, &wt);
		}
	}
	//dumpinfo(tdev);
}

static void
handle_hup(int signal) {
	if (signal == SIGHUP) {
		SIG = 1;
	}
}

static void
start(struct tundev *tdev) {
	struct sigaction sa;
	int i;
	int maxrd_fd = tdev->tunfd;
	int maxwt_fd = -1;
	fd_set rdset, wtset;
	FD_ZERO(&rdset);
	FD_ZERO(&wtset);
	FD_SET(tdev->tunfd, &rdset);
	for (i=0;i<tdev->local_n;i++) {
		int fd = tdev->localfd[i];
		if (fd >= FD_SETSIZE) {
			fprintf(stderr,"fd %d (%d) is larger than FD_SETSIZE", i, fd);
			exit(1);
		}
		FD_SET(fd, &rdset);
		FD_SET(fd, &wtset);
		if (fd > maxrd_fd)
			maxrd_fd = fd;
		if (fd > maxwt_fd)
			maxwt_fd = fd;
	}

	sa.sa_handler = &handle_hup;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		perror("handle SIGHUP");
		exit(1);
	}

	for (;;) {
		dumpinfo_hup(tdev);
		tdev->ti = time(NULL);
		forwarding(tdev, maxrd_fd+1, &rdset, maxwt_fd+1, &wtset);
	}
}

static void
ifconfig(const char * ifname, const char * va, const char *pa) {
	char cmd[1024];
        
#if defined(__APPLE__)
	snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s mtu 1380 netmask 255.255.255.255 up",
		ifname, va, pa);
#else
	snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask 255.255.255.255 pointopoint %s",
		ifname, va, pa);
#endif
	if (system(cmd) < 0) {
		perror(cmd);
		exit(1);
	}
        
}

std::vector<unsigned int> &&
get_local_ip(){
	struct ifaddrs *iflist, *ifnow;
	std::vector<unsigned int> result;
	if (getifaddrs(&iflist) == -1){
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	for (ifnow = iflist; ifnow != nullptr ; ifnow = ifnow->ifa_next){
		if(!ifnow->ifa_addr){
			continue;
		}
		int family = ifnow->ifa_addr->sa_family;
			
		if (family == AF_INET ){
			printf("%-8s",ifnow->ifa_name);
			result.push_back(((sockaddr_in *)ifnow->ifa_addr)->sin_addr.s_addr);
		}
	}
        freeifaddrs(iflist);
	return std::move(result);
}

int
main(int argc, char *argv[]) {
	int i;
	int option;
	char ifname[IFNAMSIZ] = "";
	char vpnaddress[IP_SIZE] = "";
	char ptpaddress[IP_SIZE] = "";
	struct tundev tdev;
	memset(&tdev, 0, sizeof(tdev));
	get_local_ip();
	while ((option = getopt(argc, argv, "i:v:t:r:l:p:k:")) > 0) {
		INADDR addr;
		switch(option) {
		case 'i':
			strncpy(ifname,optarg,IFNAMSIZ-1);
			break;
		case 'v':
			strncpy(vpnaddress,optarg,IP_SIZE-1);
			break;
		case 't':
			strncpy(ptpaddress,optarg,IP_SIZE-1);
			break;
		case 'p':
			tdev.port = strtol(optarg, NULL, 0); 
			break;
		case 'l':
		case 'r':
			if (inet_pton(AF_INET, optarg, &addr) <= 0) {
				fprintf(stderr, "Invalid ip : %s\n", optarg);
				return 1;
			}
			if (option == 'l') {
				if (tdev.local_n >= MAX_ADDRESS) {
					fprintf(stderr, "Too many local ip\n");
					return 1;
				}
				tdev.local[tdev.local_n++] = addr;
			} else {
				SOCKADDR *sa = &tdev.remote[tdev.remote_n];
				if (tdev.remote_n >= MAX_ADDRESS) {
					fprintf(stderr, "Too many remote ip\n");
					return 1;
				}
				++tdev.remote_n;
				sa->sin_addr = addr;
			}
			break;
		case 'k':
			tdev.key = hash_key(optarg, strlen(optarg));
			break;
		default:
			usage();
			break;
		}
	}
	if (tdev.port == 0 || ifname[0] == '\0' || vpnaddress[0] == '\0' || ptpaddress[0] == '\0') {
		usage();
		return 1;
	}

	if ((tdev.tunfd = tun_alloc(ifname)) < 0) {
		return 1;
	}

	ifconfig(ifname, vpnaddress, ptpaddress);

	if (tdev.local_n == 0) {
		INADDR *addr = &tdev.local[tdev.local_n++];
		addr->s_addr = htonl(INADDR_ANY);
	}

	for (i=0;i<tdev.local_n;i++) {
		int fd = inet_bind(&tdev.local[i], tdev.port);
		if (fd < 0) {
			// no need to close tdev.localfd[], because exit 1
			return 1;
		}
		tdev.localfd[i] = fd;
	}

	for (i=0;i<MAX_ADDRESS;i++) {
		tdev.remote[i].sin_family = AF_INET;
		tdev.remote[i].sin_port = htons(tdev.port);
	}

	start(&tdev);

	return 0;
}
