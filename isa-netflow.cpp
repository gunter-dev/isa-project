#include <iostream>
#include <iomanip>
#include <cstring>
#include <string.h>
#include <getopt.h>
#include <ctime>
#include <map>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

using namespace std;

/* ethernet headers are always exactly 14 bytes <- https://www.tcpdump.org/pcap.html */
#define SIZE_ETHERNET 14

#define ICMP 1
#define TCP 6
#define UDP 17
#define ICMPv6 58

#define IP 2048
#define IPv6 34525

// struct that represents the args
typedef struct arguments {
    char *file;
    int active_timer;
    int inactive_timer;
    int count; // TODO: count
    sockaddr_in netflow_collector;
} Arguments;

typedef struct flow {
    uint32_t srcAddr; /* source IP */
    uint32_t dstAddr; /* destination IP */
    uint32_t nextHop; /* IP address of next hop router - we don't know that */
    uint16_t input; /* SNMP index of input interface - we don't know that */
    uint16_t output; /* SNMP index of output interface - we don't know that */
    uint32_t dPkts; /* amount of packets in the flow */
    uint32_t dOctets; /* total number of Layer 3 bytes in the packets of the flow */
    uint32_t first; /* when was the first packet sent */
    uint32_t last; /* when was the last packet sent */
    uint16_t srcPort; /* source port number */
    uint16_t dstPort; /* destination port number */
    uint8_t pad1; /* unused bytes - we don't know that */
    uint8_t tcp_flags; /* TCP flags that appeared in the communication */
    uint8_t protocol; /* IP protocol type */
    uint8_t tos; /* IP type of service */
    uint16_t src_as; /* we don't know that */
    uint16_t dst_as; /* we don't know that */
    uint8_t src_mask; /* we don't know that */
    uint8_t dst_mask; /* we don't know that */
    uint16_t pad2; /* we don't know that */
} Flow;

// TODO: TOS
typedef tuple <uint32_t, uint32_t, uint16_t, uint16_t, uint8_t, uint8_t> Flow_key;

map<Flow_key, Flow> flow_cache;
typedef map<Flow_key, Flow>::iterator Iterator;
uint32_t current_packet_time;
Arguments arguments = {};

void error_exit(const char *message, uint8_t code) {
    fprintf(stderr, "%s\n", message);
    exit(code);
}

void export_flow(Flow flow) {
    int sock, i;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        error_exit("socket() failed\n", 1);

    if (connect(sock, (struct sockaddr *)&arguments.netflow_collector, sizeof(arguments.netflow_collector))  == -1)
        error_exit("connect() failed", 1);

    i = send(sock, &flow, sizeof (Flow), 0);
    if (i == -1) error_exit("send() failed", 1);
    else if (i != sizeof (Flow)) error_exit("send(): buffer written partially", 1);
}

void check_flow_timers() {
    for (Iterator it = flow_cache.begin(); it != flow_cache.end(); ++it) {
        if (it->second.first > current_packet_time - (arguments.active_timer * 1000) || it->second.last > current_packet_time - (arguments.inactive_timer * 1000)) {
            export_flow(it->second);
            flow_cache.erase(it);
        }
    }
}

void handle_flow(Flow_key key, uint8_t tcp_flags, uint32_t dOctets) {
    Iterator iterator = flow_cache.find(key);

    // according to https://cplusplus.com/reference/map/map/find/
    // std::map::find returns std::map::end if the element is not present in the map
    if (iterator == flow_cache.end()) {
        // the flow is not present, we need to insert it
        Flow flow = { get<0>(key), get<1>(key), 0, 0, 0, 1, dOctets,
                      current_packet_time, current_packet_time, get<2>(key), get<3>(key), 0,
                      tcp_flags, get<4>(key), get<5>(key), 0, 0, 0, 0, 0 };

        flow_cache.insert(make_pair(key, flow));
    } else {
        // the flow is found, we need to update it
        iterator->second.dPkts++;
        iterator->second.dOctets += dOctets;
        iterator->second.last = current_packet_time;
        iterator->second.tcp_flags |= tcp_flags;
    }
}

void icmp_packet(struct ip *iph, uint16_t protocol, uint32_t dOctets) {
    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, 0, protocol, iph->ip_tos);
    handle_flow(key, 0, dOctets);
}

/* header size is the ip header size + the ethernet header size */
void tcp_packet(const u_char *bytes, struct ip *iph, u_int header_size, uint32_t dOctets) {
    struct tcphdr *tcph = (struct tcphdr*)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, tcph->th_sport, tcph->th_dport, TCP, iph->ip_tos);
    handle_flow(key, tcph->th_flags, dOctets);
}

void udp_packet(const u_char *bytes, struct ip *iph, u_int header_size, uint32_t dOctets) {
    struct udphdr *udph = (struct udphdr *)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, udph->uh_sport, udph->uh_dport, UDP, iph->ip_tos);
    handle_flow(key, 0, dOctets);
}

void handle_ipv4(const u_char *bytes, uint32_t dOctets) {
    // the ip structure is described here -> https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
    struct ip *iph = (struct ip*)(bytes + sizeof(struct ether_header));

    switch (iph->ip_p) {
        case ICMP:
            icmp_packet(iph, ICMP, dOctets);
            break;
        case ICMPv6:
            icmp_packet(iph, ICMPv6, dOctets);
            break;
        case TCP:
            tcp_packet(bytes, iph, (iph->ip_hl * 4) + SIZE_ETHERNET, dOctets);
            break;
        case UDP:
            udp_packet(bytes, iph, (iph->ip_hl * 4) + SIZE_ETHERNET, dOctets);
            break;
    }
}

void callback (u_char *user __attribute__((unused)), const struct pcap_pkthdr *h, const u_char *bytes) {
    current_packet_time = h->ts.tv_sec*1000 + h->ts.tv_usec/1000;
    struct ether_header *header = (struct ether_header *) bytes;

    uint32_t dOctets = h->caplen - sizeof(ether_header);

    if (ntohs(header->ether_type) == IP) handle_ipv4(bytes, dOctets);
}

sockaddr_in get_default_netflow_collector() {
    sockaddr_in default_netflow_collector;
    struct hostent *servent;

    memset(&default_netflow_collector, 0, sizeof(default_netflow_collector));
    default_netflow_collector.sin_family = AF_INET;

    if ((servent = gethostbyname("127.0.0.1")) == NULL)
        error_exit("Netflow collector extracting failed", 1);

    memcpy(&default_netflow_collector.sin_addr,servent->h_addr,servent->h_length);

    default_netflow_collector.sin_port = htons(atoi("2055"));
    return default_netflow_collector;
}

void parse_arguments(int argc, char **argv) {
    // working with getopt library studied from here
    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    int idx = 0;

    static struct option options[] = {
                    { "file", required_argument, nullptr, 'f' },
                    { "netflow_collector", required_argument, nullptr, 'c' },
                    { "active_timer", required_argument, nullptr, 'a' },
                    { "inactive_timer", required_argument, nullptr, 'i' },
                    { "count", required_argument, nullptr, 'm' },
                    { nullptr, 0, nullptr, 0 }
            };

    bool done = false;

    while (!done) {
        int c = getopt_long(argc, argv, "f:c:a:i:m:", options, &idx);

        switch (c) {
            case 'f':
                arguments.file = optarg;
                break;

            case 'c':
                struct hostent *servent;

                memset(&arguments.netflow_collector, 0, sizeof(arguments.netflow_collector));
                arguments.netflow_collector.sin_family = AF_INET;

                char *ptr;
                ptr = strtok(optarg, ":");

                if ((servent = gethostbyname(ptr)) == NULL)
                    error_exit("Netflow collector extracting failed", 1);

                memcpy(&arguments.netflow_collector.sin_addr,servent->h_addr,servent->h_length);

                ptr = strtok(NULL, ":");
                if (ptr != NULL) arguments.netflow_collector.sin_port = htons(atoi(ptr));

                break;

            case 'a':
                arguments.active_timer = stoi(optarg);
                if (arguments.active_timer < 0) error_exit("ERROR: Active timer cannot be a negative number!", 1);
                break;

            case 'i':
                arguments.inactive_timer = stoi(optarg);
                if (arguments.inactive_timer < 0) error_exit("ERROR: Inactive timer cannot be a negative number!", 1);
                break;

            case 'm':
                arguments.count = stoi(optarg);
                if (arguments.count < 0) error_exit("ERROR: Flow-cache size cannot be a negative number!", 1);
                break;

            case '?':
                error_exit("ERROR: Invalid arguments!", 1);
                break;

            default:
                done = true;
                break;
        }
    }
}

int export_flows_from_pcap_file() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "icmp or tcp or udp";
    bpf_u_int32 net = 0;

    // usage of pcap_findalldevs and pcap_freealldevs is from here
    // https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        cout << "ERROR: pcap_findalldevs\n" << endl;
        return 1;
    }

    handle = pcap_open_offline(arguments.file, errbuf);

    if (!handle) {
        fprintf(stderr, "Couldn't open file %s: %s\n", arguments.file, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
    pcap_loop(handle, 0, (pcap_handler)callback, nullptr);

    pcap_close(handle);

    pcap_freealldevs(alldevsp);

    return 0;
}

int main(int argc, char **argv) {
    char stdin_selector[] = "-";
    arguments = { stdin_selector, 60, 10, 1024, get_default_netflow_collector() };
    parse_arguments(argc, argv);

    return export_flows_from_pcap_file();
}
