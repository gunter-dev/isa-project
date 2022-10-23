#include <iostream>
#include <iomanip>
#include <cstring>
#include <getopt.h>
#include <pcap/pcap.h>
#include <ctime>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

using namespace std;

// struct that represents the args
typedef struct arguments {
    char *file;
    int active_timer;
    int inactive_timer;
    int count;
} Arguments;

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

    cout << "protocol:\t" << (header->ether_type) << endl;

    if (ntohs(header->ether_type) == ETHERTYPE_IPV6) {
        // the ip6_hdr structure is described here -> https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip6.h.html
        struct ip6_hdr *iph = (struct ip6_hdr*)(bytes + sizeof(struct ether_header));
        char *ip = (char *) malloc(NI_MAXHOST);
        // https://man7.org/linux/man-pages/man3/inet_ntop.3.html
        inet_ntop(AF_INET6, &iph->ip6_src, ip, NI_MAXHOST);
        cout << "src IP:\t\t" << ip << endl;
        inet_ntop(AF_INET6, &iph->ip6_dst, ip, NI_MAXHOST);
        cout << "dst IP:\t\t" << ip << endl;
        free(ip);
    }
    else {
        // the ip structure is described here -> https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
        struct ip *iph = (struct ip*)(bytes + sizeof(struct ether_header));
        // https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html
        cout << "src IP:\t\t" << inet_ntoa(iph->ip_src) << endl;
        cout << "dst IP:\t\t" << inet_ntoa(iph->ip_dst) << endl;
    }

    cout << endl;
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
    pcap_loop(handle, 4, (pcap_handler)callback, nullptr);

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
