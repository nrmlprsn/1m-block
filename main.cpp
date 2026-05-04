#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <string>
#include <unordered_set>
#include <fstream>
#include <chrono>
#include <cctype>
#include <errno.h>
#include "hdr.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

unordered_set<string> sites;

static u_int32_t get_pkt_id (struct nfq_data *tb)
{
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(tb);
	if(ph==NULL) return 0;
	return ntohl(ph->packet_id);
}

static void normalize(string& host){
        for (size_t i = 0; i < host.length(); i++) {
                host[i] = tolower((unsigned char)host[i]);
        }
        if(!host.empty() && host.back() == '.') host.pop_back();

        auto idx = host.find(':');
        if(idx != string::npos) host = host.substr(0, idx);
}

static bool load_sites(const char* path){
	ifstream file(path);
	if(!file.is_open()) return false;
	
	sites.reserve(762564);
	string line;
	while(getline(file, line)){
		if(line.empty()) continue;

		auto comma = line.find(',');
		string host = (comma == string::npos) ? line : line.substr(comma+1);
		if(host.empty()) continue;

		if(host.back() == '\r') host.pop_back();
		normalize(host);
		if(!host.empty()) sites.insert(host);
	}

	return true;
}

static bool starts_with_http_method(const unsigned char *payload, int len)
{
    	static const char *methods[] = {
        	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        	"OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    	};
    	int i;

    	for (i = 0; i < (int)(sizeof(methods) / sizeof(methods[0])); i++) {
        	size_t mlen = strlen(methods[i]);
        	if (len >= (int)mlen && memcmp(payload, methods[i], mlen) == 0) {
            		return true;
        	}
    	}
    	return false;
}

static bool lookup_host(const string& host){
	auto st = chrono::steady_clock::now();

	if(sites.find(host) == sites.end()) return false;

	auto e = chrono::steady_clock::now();
	auto ns = chrono::duration_cast<chrono::nanoseconds>(e-st).count();

	printf("blocked host = %s, search time = %ldns\n", host.c_str(), ns);
	return true;
}

static bool is_host(unsigned char* packet, int pktlen){
	int iphdr_len, tcphdr_len, len;
	unsigned char* payload;

	ip_hdr* iphdr = (ip_hdr*)packet;
	if((iphdr->ver_ihl) >> 4 != 4) return false;
	if(iphdr->protocol != ip_hdr::TCP) return false;

	iphdr_len = ((iphdr->ver_ihl) & 0xF) << 2;
	if(iphdr_len < sizeof(ip_hdr) || pktlen <= iphdr_len + (int)sizeof(tcp_hdr)) return false;
	
	tcp_hdr* tcphdr = (tcp_hdr*)(packet + iphdr_len);
	if(ntohs(tcphdr->dst) != tcp_hdr::HTTP) return false;
	
	tcphdr_len = (((tcphdr->off_res) >> 4) & 0xF) << 2;
	if(tcphdr_len < sizeof(tcp_hdr) || pktlen <= iphdr_len + tcphdr_len) return false;

	payload = packet + iphdr_len + tcphdr_len;
	len = pktlen - iphdr_len - tcphdr_len;
	if(!starts_with_http_method(payload, len)) return false;

	for(int i=0;i<len-6;i++){
		if ((i == 0 || (i >= 2 && payload[i-2] == '\r' && payload[i-1] == '\n')) && strncasecmp((const char *)(payload + i), "Host:", 5) == 0){
			int st = i+5;
                        int vlen = 0;

                        while (st < len && (payload[st] == ' ' || payload[st] == '\t')) st++;

                        while (st+vlen < len) {
                                if(payload[st+vlen] == '\r') break;
				if(payload[st+vlen] == '\n') break;
				if(payload[st+vlen] == ' ') break;
                                vlen++;
                        }
                        if(!vlen) continue;
			
			string host = string((const char*)(payload+st), vlen);
			normalize(host);
			return lookup_host(host);
		}
	}

	return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int pktlen;
	unsigned char* packet;

	uint32_t id = get_pkt_id(nfa);
	pktlen = nfq_get_payload(nfa, &packet);

	if(pktlen >= 0 && is_host(packet, pktlen))
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage(){
	printf("syntax: 1m-block <site list file>\n");
	printf("sample: 1m-block top-1m.txt\n");
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2){
		usage();
		return 1;
	}
	
	auto st = chrono::steady_clock::now();
	if(!load_sites(argv[1])){
		fprintf(stderr, "error reading file %s\n", argv[1]);
		exit(1);
	}
	auto e = chrono::steady_clock::now();
	auto ns = chrono::duration_cast<chrono::nanoseconds>(e-st).count();

	printf("loaded %zu sites in %ldns\n", sites.size(), ns);

	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	nfq_unbind_pf(h, AF_INET);
#endif

	nfq_close(h);

	exit(0);
}

