#include <iostream>
#include <iomanip>
#include <cstring>
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
    int count; // TODO: count and netflow_collector
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
typedef tuple <uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> Flow_key;

map<Flow_key, Flow> flow_cache;
typedef map<Flow_key, Flow>::iterator Iterator;
uint32_t current_packet_time;
Arguments arguments = {};

void error_exit(const char *message, uint8_t code) {
    fprintf(stderr, "%s\n", message);
    exit(code);
}

void check_flow_timers() {
    for (Iterator it = flow_cache.begin(); it != flow_cache.end(); ++it) {
        if (it->second.first > current_packet_time - (arguments.active_timer * 1000) || it->second.last > current_packet_time - (arguments.inactive_timer * 1000)) {
            // TODO: export flow
            flow_cache.erase(it);
        }
    }
}

void handle_flow(Flow_key key, uint8_t tcp_flags) {
    // https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html
    cout << "protocol:\t" << unsigned(get<4>(key)) << endl;
    cout << "src IP:\t\t" << get<0>(key) << ":" << ntohs(get<2>(key)) << endl;
    cout << "dst IP:\t\t" << get<1>(key) << ":" << ntohs(get<3>(key)) << endl;

    Iterator iterator = flow_cache.find(key);

    // according to https://cplusplus.com/reference/map/map/find/
    // std::map::find returns std::map::end if the element is not present in the map
    if (iterator == flow_cache.end()) {
        // the flow is not present, we need to insert it
        Flow flow = { get<0>(key), get<1>(key), 0, 0, 0, 1, 0,
                      current_packet_time, current_packet_time, get<2>(key), get<3>(key), 0,
                      tcp_flags, get<4>(key), 0, 0, 0, 0, 0, 0 };

        flow_cache.insert(make_pair(key, flow));
    } else {
        // the flow is found, we need to update it
        iterator->second.dPkts++;
        iterator->second.last = current_packet_time;
        iterator->second.tcp_flags |= tcp_flags;
    }
}

void icmp_packet(const u_char *bytes, struct ip *iph, uint16_t protocol) {
    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, 0, protocol);
    handle_flow(key, 0);
}

/* header size is the ip header size + the ethernet header size */
void tcp_packet(const u_char *bytes, struct ip *iph, u_int header_size) {
    struct tcphdr *tcph = (struct tcphdr*)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, tcph->th_sport, tcph->th_dport, TCP);
    handle_flow(key, tcph->th_flags);
}

void udp_packet(const u_char *bytes, struct ip *iph, u_int header_size) {
    struct udphdr *udph = (struct udphdr *)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, udph->uh_sport, udph->uh_dport, UDP);
    handle_flow(key, 0);
}

void handle_ipv4(const u_char *bytes) {
    // the ip structure is described here -> https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
    struct ip *iph = (struct ip*)(bytes + sizeof(struct ether_header));

    switch (iph->ip_p) {
        case ICMP:
            icmp_packet(bytes, iph, ICMP);
            break;
        case ICMPv6:
            icmp_packet(bytes, iph, ICMPv6);
            break;
        case TCP:
            tcp_packet(bytes, iph, (iph->ip_hl * 4) + SIZE_ETHERNET);
            break;
        case UDP:
            udp_packet(bytes, iph, (iph->ip_hl * 4) + SIZE_ETHERNET);
            break;
    }

    cout << endl;
}

void callback (u_char *user __attribute__((unused)), const struct pcap_pkthdr *h, const u_char *bytes) {
/*    // h->ts has this structure -> https://renenyffenegger.ch/notes/development/languages/C-C-plus-plus/C/libc/structs/timeval
    tm *ptm = localtime(&h->ts.tv_sec);
    char date[11];
    char time[9];
    // got this from strftime documentation -> https://en.cppreference.com/w/cpp/chrono/c/strftime
    strftime(date, 11, "%F", ptm);
    strftime(time, 9, "%T", ptm);

    cout << "date:\t\t" << date << endl;
    cout << "time:\t\t" << time << ".";
    // setfill and setw makes sure, that the millisecond part is printed correctly
    // for example 50 milliseconds should be printed as 050 milliseconds
    // https://www.cplusplus.com/reference/iomanip/setfill/
    cout << setfill('0') << setw(3);
    // h->ts.tv_usec is divided to get time in milliseconds
    cout << h->ts.tv_usec/1000 << endl;*/

    current_packet_time = h->ts.tv_sec*1000 + h->ts.tv_usec/1000;
    struct ether_header *header = (struct ether_header *) bytes;

    if (ntohs(header->ether_type) == IP) handle_ipv4(bytes);
}

void parse_arguments(int argc, char **argv) {
    // working with getopt library studied from here
    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    int idx = 0;

    static struct option options[] = {
                    { "file", required_argument, nullptr, 'f' },
                    { "active_timer", required_argument, nullptr, 'a' },
                    { "inactive_timer", required_argument, nullptr, 'i' },
                    { "count", required_argument, nullptr, 'm' },
                    { nullptr, 0, nullptr, 0 }
            };

    bool done = false;

    while (!done) {
        int c = getopt_long(argc, argv, "f:a:i:m:", options, &idx);

        switch (c) {
            case 'f':
                arguments.file = optarg;
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
    arguments = { stdin_selector, 60, 10, 1024 };
    parse_arguments(argc, argv);

    return export_flows_from_pcap_file();
}
