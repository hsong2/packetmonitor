#include "callback.h"

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *ep;
    unsigned short ether_type;

    ep = (struct ether_header *)packet;

    packet += sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);

    if(ether_type == ETHERTYPE_IP) {
        iph = (struct ip *)packet;
        if(iph->ip_p == IPPROTO_TCP) {
            printf("Src Mac : %02X:%02X:%02X:%02X:%02X:%02X\n"
                   , ep->ether_shost[0], ep->ether_shost[1],
                    ep->ether_shost[2], ep->ether_shost[3],
                    ep->ether_shost[4], ep->ether_shost[5]);
            printf("Dst Mac : %02X:%02X:%02X:%02X:%02X:%02X\n"
                   , ep->ether_dhost[0], ep->ether_dhost[1],
                    ep->ether_dhost[2], ep->ether_dhost[3],
                    ep->ether_dhost[4], ep->ether_dhost[5]);
            printf("Src IP : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst IP : %s\n", inet_ntoa(iph->ip_dst));
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n", ntohs(tcph->source));
            printf("Dst Port : %d\n", ntohs(tcph->dest));
            printf("----------------------------------------\n");
        } else {
            printf("NONE TCP Packet\n");
        }
    } else {
        printf("NONE IP Packet\n");
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *pcd;
    struct bpf_program fp;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    int ret;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(pcd, &fp, argv[2], 0, netp) == -1) {
        printf("compile error\n");
        exit(1);
    }
    if(pcap_setfilter(pcd, &fp) == -1) {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(pcd, atoi(argv[1]), callback, NULL);

    return 0;
}
