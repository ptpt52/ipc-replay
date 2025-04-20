#define _GNU_SOURCE
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

unsigned short ip_checksum(unsigned short *buf, int nwords) {
	unsigned long sum = 0;
	for (; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, uint8_t *data, int data_len) {
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t zero;
		uint8_t proto;
		uint16_t udp_len;
	} __attribute__((packed)) pseudo_header;

	pseudo_header.src = ip->saddr;
	pseudo_header.dst = ip->daddr;
	pseudo_header.zero = 0;
	pseudo_header.proto = IPPROTO_UDP;
	pseudo_header.udp_len = htons(sizeof(struct udphdr) + data_len);

	int pseudo_len = sizeof(pseudo_header);
	int udp_len = sizeof(struct udphdr) + data_len;
	int total_len = pseudo_len + udp_len;

	uint8_t *buf = malloc(total_len + 1); // +1 for padding
	if (!buf) return 0;

	memcpy(buf, &pseudo_header, pseudo_len);
	memcpy(buf + pseudo_len, udp, sizeof(struct udphdr));
	memcpy(buf + pseudo_len + sizeof(struct udphdr), data, data_len);

	if (total_len % 2 == 1) {
		buf[total_len] = 0;
		total_len++;
	}

	uint32_t sum = 0;
	for (int i = 0; i < total_len; i += 2)
		sum += (buf[i] << 8) + buf[i + 1];

	free(buf);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return htons(~sum & 0xFFFF);
}

int main(int argc, char *argv[]) {
	unsigned int ip1 = 0, ip2 = 0, ip3 = 0;
	const char *recv_iface;
	const char *send_iface;
	const char *src_str = NULL;
	const char *dst_str = NULL;
	int replace_payload = 0;

	if (argc < 3) {
		fprintf(stderr, "用法: %s <recv_if> <send_if> [new_ip_prefix] [src_str dst_str]\n", argv[0]);
		return 1;
	}

	if (argc >= 4 && strchr(argv[3], '.') != NULL) {
		if (sscanf(argv[3], "%u.%u.%u", &ip1, &ip2, &ip3) != 3 ||
		        ip1 > 255 || ip2 > 255 || ip3 > 255) {
			fprintf(stderr, "非法的 IP 前缀: %s\n", argv[3]);
			return 1;
		}
		if (argc >= 6) {
			src_str = argv[4];
			dst_str = argv[5];
			if (strlen(dst_str) > strlen(src_str)) {
				fprintf(stderr, "目标字符串长度不能大于源字符串长度\n");
				return 1;
			}
			replace_payload = 1;
		}
	} else if (argc >= 5) {
		src_str = argv[3];
		dst_str = argv[4];
		if (strlen(dst_str) > strlen(src_str)) {
			fprintf(stderr, "目标字符串长度不能大于源字符串长度\n");
			return 1;
		}
		replace_payload = 1;
	}

	recv_iface = argv[1];
	send_iface = argv[2];

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
		if (len < 42) continue;

		struct ethhdr *eth = (struct ethhdr *)buffer;

		if (memcmp(eth->h_dest, "\xff\xff\xff\xff\xff\xff", 6) != 0)
			continue;

		if (ntohs(eth->h_proto) != ETH_P_IP)
			continue;

		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
		if (ip->protocol != IPPROTO_UDP)
			continue;

		if (ip->frag_off & htons(0x3FFF))
			continue;

		uint32_t dst_ip = ntohl(ip->daddr);
		if ((dst_ip & 0xFF) != 0xFF)
			continue;

		struct udphdr *udp = (struct udphdr *)(ip + 1);
		uint8_t *udp_payload = (uint8_t *)(udp + 1);
		int udp_data_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

		if (ip1 || ip2 || ip3) {
			uint32_t new_src_ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | (ntohl(ip->saddr) & 0xFF);
			uint32_t new_dst_ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | 255;
			ip->saddr = htonl(new_src_ip);
			ip->daddr = htonl(new_dst_ip);
		}

		if (replace_payload && src_str && dst_str) {
			int src_len = strlen(src_str);
			int dst_len = strlen(dst_str);

			uint8_t *found = memmem(udp_payload, udp_data_len, src_str, strlen(src_str));
			if (found) {
				int offset = found - udp_payload;
				int tail_len = udp_data_len - offset - src_len;

				// 移动尾部数据，扩大或缩小空间
				if (dst_len != src_len) {
					memmove(found + dst_len, found + src_len, tail_len);
				}
				memcpy(found, dst_str, dst_len);

				// 更新 UDP 和 IP 长度字段
				udp_data_len = udp_data_len - src_len + dst_len;
				udp->uh_ulen = htons(ntohs(udp->uh_ulen) - src_len + dst_len);
				ip->tot_len = htons(ntohs(ip->tot_len) - src_len + dst_len);
				len = len - src_len + dst_len;
			}
		}

		ip->check = 0;
		ip->check = ip_checksum((unsigned short *)ip, ip->ihl * 2);

		udp->uh_sum = 0;
		udp->uh_sum = udp_checksum(ip, udp, udp_payload, udp_data_len);

		memcpy(eth->h_source, send_iface_mac, 6);

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
