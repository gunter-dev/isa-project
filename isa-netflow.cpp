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
    int count;
} Arguments;

typedef struct flow {
    uint32_t dPkts; /* amount of packets */
    uint32_t dOctets;
    timeval first; /* when was the first packet sent */
    timeval last; /* when was the last packet sent */
    char *tcp_flags; /* tcp flags that appeared in the communication */
} Flow;

// TODO: TOS
typedef tuple <uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> Flow_key;

map<Flow_key, Flow> flow_cache;

void handle_flow(Flow_key key) {
    // https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html
    cout << "protocol:\t" << get<4>(key) << endl;
    cout << "src IP:\t\t" << get<0>(key) << ":" << ntohs(get<2>(key)) << endl;
    cout << "dst IP:\t\t" << get<1>(key) << ":" << ntohs(get<3>(key)) << endl;

    // TODO: check_flow_timers()

    // TODO: tcp_flags
    char test[] = "-";

    Flow todo_flow = { 0, 0, 0, 0, 0, 0, test };

    if (flow_cache.find(key) == flow_cache.end()) {
        flow_cache.insert(make_pair(key, todo_flow));
    } else {
        cout << "found" << endl;
    }
}

void icmp_packet(const u_char *bytes, struct ip *iph, uint16_t protocol) {
    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, 0, protocol);
    handle_flow(key);
}

/* header size is the ip header size + the ethernet header size */
void tcp_packet(const u_char *bytes, struct ip *iph, u_int header_size) {
    struct tcphdr *tcph = (struct tcphdr*)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, tcph->th_sport, tcph->th_dport, TCP);
    handle_flow(key);
}

void udp_packet(const u_char *bytes, struct ip *iph, u_int header_size) {
    struct udphdr *udph = (struct udphdr *)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, udph->uh_sport, udph->uh_dport, UDP);
    handle_flow(key);
}

void handle_ipv6(const u_char *bytes) {
        // the ip6_hdr structure is described here -> https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip6.h.html
        struct ip6_hdr *iph = (struct ip6_hdr*)(bytes + sizeof(struct ether_header));

        char *src_ip = (char *) malloc(NI_MAXHOST);
        char *dst_ip = (char *) malloc(NI_MAXHOST);

        // https://man7.org/linux/man-pages/man3/inet_ntop.3.html
        inet_ntop(AF_INET6, &iph->ip6_src, src_ip, NI_MAXHOST);
        inet_ntop(AF_INET6, &iph->ip6_dst, dst_ip, NI_MAXHOST);

//        Flow_key key = { src_ip, dst_ip, icmp_port, icmp_port, header->ether_type };
//        handle_flow(key);

        free(src_ip);
        free(dst_ip);
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
    // h->ts has this structure -> https://renenyffenegger.ch/notes/development/languages/C-C-plus-plus/C/libc/structs/timeval
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
    cout << h->ts.tv_usec/1000 << endl;

    struct ether_header *header = (struct ether_header *) bytes;

    if (ntohs(header->ether_type) == IPv6) handle_ipv6(bytes);
    else if (ntohs(header->ether_type) == IP) handle_ipv4(bytes);
}

void parse_arguments(int argc, char **argv, Arguments *arguments) {
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

    while (true) {
        bool done = false;
        int c = getopt_long(argc, argv, "f:a:i:m:", options, &idx);

        switch (c) {
            case 'f':
                arguments->file = optarg;
                break;

            case 'a':
                arguments->active_timer = stoi(optarg);
                if (arguments->active_timer < 0) {
                    fprintf(stderr, "ERROR: Active timer cannot be a negative number!\n");
                    exit(1);
                }
                break;

            case 'i':
                arguments->inactive_timer = stoi(optarg);
                if (arguments->inactive_timer < 0) {
                    fprintf(stderr, "ERROR: Inactive timer cannot be a negative number!\n");
                    exit(1);
                }
                break;

            case 'm':
                arguments->count = stoi(optarg);
                if (arguments->count < 0) {
                    fprintf(stderr, "ERROR: Flow-cache size cannot be a negative number!\n");
                    exit(1);
                }
                break;

            case '?':
                fprintf(stderr, "ERROR: Invalid arguments!\n");
                exit(1);

            default:
                done = true;
                break;
        }

        if (done) break;
    }
}

int export_flows_from_pcap_file(Arguments arguments) {
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
    Arguments arguments = { stdin_selector, 60, 10, 1024 };
    parse_arguments(argc, argv, &arguments);

    return export_flows_from_pcap_file(arguments);
}
