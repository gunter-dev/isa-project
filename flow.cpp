#include <iostream>
#include <iomanip>
#include <cstring>
#include <string.h>
#include <getopt.h>
#include <math.h>
#include <ctime>
#include <map>
#include <algorithm>

#define __FAVOR_BSD

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

/* struct that represents the args */
typedef struct arguments {
    char *file;                     /* input file, is "-" (for STDIN) by default */
    sockaddr_in netflow_collector;  /* IP address (possibly with port) of the NetFlow collector */
    uint32_t active_timer;               /* time in seconds, after which active flows are exported, 60 by default */
    uint32_t inactive_timer;             /* time in seconds, after which inactive flows are exported, 10 by default */
    size_t count;                   /* if the amount of flows in flow cache reaches this number, export the oldest, 1024 by default */
} Arguments;

/* struct representing the whole flow
 * properties marked by "UNKNOWN" in the comment I set to 0 by default
 * since we don't know, what their values should be
 *
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1003394
 */
typedef struct flow {
    /*--------------------- FLOW HEADER ---------------------*/
    uint16_t version;       /* NetFlow export format version number */
    uint16_t count;         /* amount of flows exported in the single packet */
    uint32_t sys_uptime;    /* current time in milliseconds since the export device booted */
    uint32_t unix_secs;     /* current count of seconds since 0000 UTC 1970 */
    uint32_t unix_nsecs;    /* residual current count of seconds since 0000 UTC 1970 */
    uint32_t flow_sequence; /* sequence counter of total flows seen */
    uint8_t engine_type;    /* type of flow-switching engine - UNKNOWN */
    uint8_t engine_id;      /* slot number of the flow-switching engine - UNKNOWN */
    uint16_t samp_interval; /* first two bits hold the sampling mode; remaining 14 bits hold value of sampling interval - UNKNOWN */
    /*--------------------- FLOW RECORD ---------------------*/
    uint32_t srcAddr;       /* source IP */
    uint32_t dstAddr;       /* destination IP */
    uint32_t nextHop;       /* IP address of next hop router - UNKNOWN */
    uint16_t input;         /* SNMP index of input interface - UNKNOWN */
    uint16_t output;        /* SNMP index of output interface - UNKNOWN */
    uint32_t dPkts;         /* amount of packets in the flow */
    uint32_t dOctets;       /* total number of Layer 3 bytes in the packets of the flow */
    uint32_t first;         /* when was the first packet sent */
    uint32_t last;          /* when was the last packet sent */
    uint16_t srcPort;       /* source port number */
    uint16_t dstPort;       /* destination port number */
    uint8_t pad1;           /* unused bytes - UNKNOWN */
    uint8_t tcp_flags;      /* TCP flags that appeared in the communication */
    uint8_t protocol;       /* IP protocol type */
    uint8_t tos;            /* IP type of service */
    uint16_t src_as;        /* UNKNOWN */
    uint16_t dst_as;        /* UNKNOWN */
    uint8_t src_mask;       /* UNKNOWN */
    uint8_t dst_mask;       /* UNKNOWN */
    uint16_t pad2;          /* UNKNOWN */
} Flow;

/* a key used for the flow_cache map, this is what is used for indexing
 * the structure is as follows:
 * - source IP address (uint32_t)
 * - destination IP address (uint32_t)
 * - source port (uint16_t)
 * - destination port (uint16_t)
 * - protocol (uint8_t)
 * - type of service (uint8_t)
 * */
typedef tuple <uint32_t, uint32_t, uint16_t, uint16_t, uint8_t, uint8_t> Flow_key;

/* global variables */
map<Flow_key, Flow> flow_cache;
typedef map<Flow_key, Flow>::iterator Iterator;
Arguments arguments = {};

timeval current_packet_timeval;
uint32_t boot_time = 0;
uint32_t flow_sequence = 0;
uint32_t header_sys_uptime;
bool header_sys_uptime_initialized = false;

/**
 * When an error occurs, this function is called. It prints a message that is
 * passed to it (it also prints a newline character so I don't need to pass it
 * in the string all the time) and exits the app with a passed error code.
 *
 * @param message the message, that is printed to stderr
 * @param code error code, with which the app terminates
 * */
void error_exit(const char *message, uint8_t code) {
    fprintf(stderr, "%s\n", message);
    exit(code);
}

/**
 * Send a flow to the NetFlow collector specified in the arguments (or the default one).
 *
 * @param flow The flow to be sent
 * */
void export_flow(Flow flow) {
    flow.dPkts = ntohl(flow.dPkts);
    flow.dOctets = ntohl(flow.dOctets);
    flow.first = ntohl(flow.first);
    flow.last = ntohl(flow.last);
    flow.flow_sequence = ntohl(flow_sequence++);

    int sock, i;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        error_exit("socket() failed\n", 1);

    if (connect(sock, (struct sockaddr *)&arguments.netflow_collector, sizeof(arguments.netflow_collector))  == -1)
        error_exit("connect() failed", 1);

    i = send(sock, &flow, sizeof (Flow), 0);
    if (i == -1) error_exit("send() failed", 1);
    else if (i != sizeof (Flow)) error_exit("send(): buffer written partially", 1);
}

/**
 * Goes through every single flow in the flow cache and checks its timers.
 * If the flow is active for more than the amount of seconds specified
 * in the active_timer argument or if it had been inactive for more than
 * the amount of seconds specified in the inactive_timer, it is exported.
 * */
void check_flow_timers(uint32_t sys_uptime) {
    // deleting according to this stack overflow site -> https://stackoverflow.com/questions/8234779/how-to-remove-from-a-map-while-iterating-it
    Iterator oldest = flow_cache.begin();

    for (Iterator it = oldest; it != flow_cache.end(); /* empty on purpose */) {
        bool active_invalid = arguments.active_timer * 1000 < sys_uptime && it->second.first < sys_uptime - (arguments.active_timer * 1000);
        bool inactive_invalid = arguments.inactive_timer * 1000 < sys_uptime && it->second.last < sys_uptime - (arguments.inactive_timer * 1000);
        if (active_invalid || inactive_invalid) {
            export_flow(it->second);
            it = flow_cache.erase(it);
        } else {
            if (oldest->first > it->first) oldest = it;
            ++it;
        }
    }

    if (arguments.count <= flow_cache.size()) {
        export_flow(oldest->second);
        flow_cache.erase(oldest);
    }
}

void check_tcp_flags() {
    for (Iterator it = flow_cache.begin(); it != flow_cache.end(); /* empty on purpose */) {
        if ((it->second.tcp_flags & (1 << 2)) || (it->second.tcp_flags & 1)) {
            export_flow(it->second);
            it = flow_cache.erase(it);
        } else {
            ++it;
        }
    }
}

/**
 * For each packet this function is called. It attempts to find the according
 * flow in the flow cache. If it doesn't find it, new flow is created and
 * inserted to the flow cache. Else it updates the corresponding flow.
 *
 * @param key used for searching and indexing in the flow cache
 * @param tcp_flags tcp_flags exported from the packet earlier
 * @param dOctets dOctets are calculated earlier from the ether_header
 * */
void handle_flow(Flow_key key, uint8_t tcp_flags, uint32_t dOctets) {
    uint32_t current_packet_time = current_packet_timeval.tv_sec * 1000 + current_packet_timeval.tv_usec / 1000;

    uint32_t sys_uptime = current_packet_time - boot_time;
    if (!header_sys_uptime_initialized) {
        header_sys_uptime = sys_uptime;
        header_sys_uptime_initialized = true;
    }

    check_flow_timers(sys_uptime);

    Iterator iterator = flow_cache.find(key);

    // according to https://cplusplus.com/reference/map/map/find/
    // std::map::find returns std::map::end if the element is not present in the map
    if (iterator == flow_cache.end()) {
        // the flow is not present, we need to insert it
        Flow flow = { ntohs(5),  ntohs(1), ntohl(header_sys_uptime), ntohl(current_packet_timeval.tv_sec),
                      ntohl(current_packet_timeval.tv_usec*1000), 0, 0, 0, 0, get<0>(key), get<1>(key), 0,
                      0, 0, 1, dOctets, sys_uptime, sys_uptime, get<2>(key), get<3>(key), 0, tcp_flags,
                      get<4>(key), get<5>(key), 0, 0, 0, 0, 0 };

        flow_cache.insert(make_pair(key, flow));
    } else {
        // the flow is found, we need to update it
        iterator->second.dPkts++;
        iterator->second.dOctets += dOctets;
        iterator->second.last = sys_uptime;
        iterator->second.tcp_flags |= tcp_flags;
    }

    check_tcp_flags();
}

/**
 * Creates a flow key for the ICMP packet
 * */
void icmp_packet(struct ip *iph, uint16_t protocol, uint32_t dOctets) {
    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, 0, protocol, iph->ip_tos);
    handle_flow(key, 0, dOctets);
}

/**
 * Creates a flow key for the TCP packet
 *
 * @param bytes the packet
 * @param iph IP header
 * @param header_size the ip header size + the ethernet header size
 * */
void tcp_packet(const u_char *bytes, struct ip *iph, u_int header_size, uint32_t dOctets) {
    struct tcphdr *tcph = (struct tcphdr*)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, tcph->th_sport, tcph->th_dport, TCP, iph->ip_tos);
    handle_flow(key, tcph->th_flags, dOctets);
}

/**
 * Creates a flow key for the UDP packet
 *
 * @param bytes the packet
 * @param iph IP header
 * @param header_size the ip header size + the ethernet header size
 * */
void udp_packet(const u_char *bytes, struct ip *iph, u_int header_size, uint32_t dOctets) {
    struct udphdr *udph = (struct udphdr *)(bytes + header_size);

    Flow_key key(iph->ip_src.s_addr, iph->ip_dst.s_addr, udph->uh_sport, udph->uh_dport, UDP, iph->ip_tos);
    handle_flow(key, 0, dOctets);
}

/**
 * Finds out the packet type (ICMP/UDP/TCP) and calls the corresponding function.
 *
 * @param bytes the packet
 * @param dOctets dOctets calculated earlier from the packet header - only to pass it forward
 * */
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

/**
 * The pcap_loop function calls this function for every packet from the input.
 * Finds out the time of the packet and saves it to a global variable. Then calculates
 * dOctets (caplen from packet header - the size of ether_header). Finally calls
 * the next function only if the packet is IPv4. I do not support NetFlow v9, so I
 * do not have function for IPv6.
 *
 * @param user unused parameter, it is passed from the pcap_loop function, but I don't need it
 * @param h the packet header
 * @param bytes the packet itself
 * */
void callback (u_char *user __attribute__((unused)), const struct pcap_pkthdr *h, const u_char *bytes) {
    if (boot_time == 0) boot_time = h->ts.tv_sec * 1000 + h->ts.tv_usec / 1000;

    current_packet_timeval = h->ts;
    struct ether_header *header = (struct ether_header *) bytes;

    uint32_t dOctets = h->caplen - sizeof(ether_header);

    if (ntohs(header->ether_type) == IP) handle_ipv4(bytes, dOctets);
}

/**
 * Returns the default netflow collector specified in the task (127.0.0.1:2055).
 *
 * @return default netflow collector
 * */
sockaddr_in get_default_netflow_collector() {
    sockaddr_in default_netflow_collector;
    struct hostent *servent;

    memset(&default_netflow_collector, 0, sizeof(default_netflow_collector));
    default_netflow_collector.sin_family = AF_INET;

    if ((servent = gethostbyname("127.0.0.1")) == nullptr)
        error_exit("Netflow collector extracting failed", 1);

    memcpy(&default_netflow_collector.sin_addr,servent->h_addr,servent->h_length);

    default_netflow_collector.sin_port = htons(atoi("2055"));
    return default_netflow_collector;
}

/**
 * Using getopt library parses arguments and stores them in the global struct for arguments.
 *
 * @param argc amount of arguments
 * @param argv array containing the arguments
 * */
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

                if ((servent = gethostbyname(ptr)) == nullptr)
                    error_exit("Netflow collector extracting failed", 1);

                memcpy(&arguments.netflow_collector.sin_addr,servent->h_addr,servent->h_length);

                ptr = strtok(nullptr, ":");
                if (ptr != nullptr) arguments.netflow_collector.sin_port = htons(atoi(ptr));

                break;

            case 'a':
                if (stoi(optarg) < 0) error_exit("ERROR: Active timer cannot be a negative number!", 1);
                arguments.active_timer = stoi(optarg);
                break;

            case 'i':
                if (stoi(optarg) < 0) error_exit("ERROR: Inactive timer cannot be a negative number!", 1);
                arguments.inactive_timer = stoi(optarg);
                break;

            case 'm':
                if (stoi(optarg) < 0) error_exit("ERROR: Flow-cache size cannot be a negative number!", 1);
                arguments.count = stoi(optarg);
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

void export_remaining_flows_in_map() {
    while (!flow_cache.empty()) {
        Iterator oldest = min_element(flow_cache.begin(), flow_cache.end(),
                                      [](Iterator::value_type &l, Iterator::value_type &r) -> bool {
                                          return l.second.first < r.second.first;
                                      });
        export_flow(oldest->second);
        flow_cache.erase(oldest);
    }
}

/**
 * The primary function working mainly with the pcap library.
 *
 * @return the error code
 * */
int export_flows_from_pcap_file() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "icmp or tcp or udp";
    bpf_u_int32 net = 0;

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
    export_remaining_flows_in_map();

    pcap_close(handle);

    return 0;
}

int main(int argc, char **argv) {
    char stdin_selector[] = "-";
    arguments = { stdin_selector, get_default_netflow_collector(), 60, 10, 1024 };
    parse_arguments(argc, argv);

    return export_flows_from_pcap_file();
}
