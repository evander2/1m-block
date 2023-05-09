// gcc -o nfqnl_test nfqnl_test.c -lnetfilter_queue

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h>
#include <time.h>



typedef struct {
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
}TCP;


/* dump */
void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


struct Malicious_hosts{
	char name[50];
};

struct Malicious_hosts m_hosts[1000100];
int cnt = 0;
int packet_check;

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
		printf("payload_len=%d ", ret);


		IP *iph = (IP *)(data);
		data += (iph->v_l&0xF)*4;
		ret -= (iph->v_l&0xF)*4;

		TCP *tcph = (TCP *)(data);
		data += tcph->offset_reserved>>2;	
		ret -= tcph->offset_reserved>>2;
	

		int http_end = 0;
		for(int i = 0; i <= ret; i += 1){
			if(*((uint32_t *)(data+i))==0x0a0d0a0d){
				http_end = i;
				break;
			}
		}

		const char stp[8] = "\r\nHost: ";
		for(int i = 0; i < http_end; i++){
			if(!memcmp(data+i, stp, 8)){
				int host_start = i+8;
				int host_end = http_end;
				for(int j = host_start; j < http_end; j++){
					if(*((uint16_t *)(data+j))==0x0a0d){
						host_end = j;
						break;
					}
				}
				int host_len = host_end - host_start;
				
				for(int i=0; i<cnt; i++){
					packet_check = memcmp(m_hosts[i].name, data+host_start, host_len)?0:1;
					if(packet_check){
						break;
					}
				}	
				break;
			}
		}
	}
	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	packet_check = 0;
	uint32_t id = print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, packet_check?NF_DROP:NF_ACCEPT, 0, NULL);
}


void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}


void search_time(){

	double st,ed;
	char *test = "testestest.test";
	int check = 0;
	st = (double)clock()/CLOCKS_PER_SEC;
	for(int i=0; i<cnt; i++){
		check = memcmp(m_hosts[i].name, test, strlen(test))?0:1;
		if(check){
			break;
		}
	}
	ed = (double)clock()/CLOCKS_PER_SEC;
	printf("%lf second\n", ed-st);

}


void get_csv(char *file_name){
	const int line_length = 1024;
	
	FILE *file = fopen(file_name, "r");
	if(file==NULL){
		printf("Failed to open file.\n");
		exit(1);
	}
	cnt = 0;
	char line[line_length];
	while(fgets(line, sizeof(line), file)){
		char *token;
		token = strtok(line, ",");
		token = strtok(NULL, ",");
		memcpy(m_hosts[cnt++].name, token, strlen(token));
	}
	fclose(file);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		usage();
		exit(-1);
	}
	get_csv(argv[1]);
	//search_time();

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
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

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
