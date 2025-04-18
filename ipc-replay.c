#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048

int get_iface_mac(const char *iface, unsigned char *mac) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	struct ifreq ifr;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		close(fd);
		return -1;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
	return 0;
}

int bind_raw_socket(const char *iface, int protocol) {
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
	if (sockfd < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_ll sll = {0};
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(protocol);
	sll.sll_ifindex = if_nametoindex(iface);
	if (sll.sll_ifindex == 0) {
		perror("if_nametoindex");
		exit(1);
	}

	if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind");
		exit(1);
	}

	return sockfd;
}

void print_mac(const char *label, const unsigned char *mac) {
	printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", label,
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char *argv[]) {
	if (argc != 3) {
		fprintf(stderr, "用法: %s <接收接口> <发送接口>\n", argv[0]);
		return 1;
	}

	const char *recv_iface = argv[1];
	const char *send_iface = argv[2];

	unsigned char send_iface_mac[6];
	if (get_iface_mac(send_iface, send_iface_mac) != 0) {
		perror("获取发送接口 MAC 失败");
		return 1;
	}
	print_mac("使用发送接口 MAC:", send_iface_mac);

	int recv_sock = bind_raw_socket(recv_iface, ETH_P_ALL);
	int send_sock = bind_raw_socket(send_iface, ETH_P_ALL);

	unsigned char buffer[BUFFER_SIZE];

	printf("监听接口: %s，转发至接口: %s\n", recv_iface, send_iface);

	while (1) {
		ssize_t len = recv(recv_sock, buffer, sizeof(buffer), 0);
		if (len < 42) continue; // 最小以太 + IP + UDP 长度

		struct ethhdr *eth = (struct ethhdr *)buffer;

		// 过滤：目的 MAC 必须是广播
		if (memcmp(eth->h_dest, "\xff\xff\xff\xff\xff\xff", 6) != 0)
			continue;

		// 检查以太类型是 IPv4
		if (ntohs(eth->h_proto) != ETH_P_IP)
			continue;

		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
		if (ip->protocol != IPPROTO_UDP)
			continue;

		// ✅ 过滤 IP 分片包
		if (ip->frag_off & htons(0x3FFF)) {
			//printf("跳过 IP 分片包\n");
			continue;
		}

		// 检查目标 IP 是否广播（最后一字节为 255）
		uint32_t dst_ip = ntohl(ip->daddr);
		if ((dst_ip & 0xFF) != 0xFF)
			continue;

		// 替换源 MAC 为发送接口 MAC
		memcpy(eth->h_source, send_iface_mac, 6);

		// 发送出去
		if (send(send_sock, buffer, len, 0) < 0) {
			perror("发送失败");
		} else {
			printf("转发 %zd 字节的广播包\n", len);
		}
	}

	close(recv_sock);
	close(send_sock);
	return 0;
}
