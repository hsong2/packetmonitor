#pragma once
#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define NONPROMISCUOUS 0

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);
