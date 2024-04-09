#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <regex.h>

#define MAX_MATCHES 10
#define MAX_GROUP_LENGTH 100

char group[MAX_GROUP_LENGTH];
const char* netfilter_host;

void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net");
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void parse_packet(unsigned char* data, int size) {
    if (data[9] == 0x06) { // 0x06 is TCP
        int ip_header_length = (data[0] & 0x0F) * 4; // IP header len
        int tcp_header_length = ((data[ip_header_length+12] & 0xF0) >> 4) * 4; // TCP header len
        int data_offset = ip_header_length + tcp_header_length;
        int http_data_length = size - data_offset;
        if (http_data_length > 0) {
            unsigned char* http_data = data + data_offset;
            regex_t reg;
            const char * pattern = "Host: ([a-z\.]*)";
            regcomp(&reg, pattern, REG_EXTENDED);

            regmatch_t matches[MAX_MATCHES];

            if(!regexec(&reg, http_data, MAX_MATCHES, matches, 0)) {
                if(matches[1].rm_so != -1) {
                    int group_length = matches[1].rm_eo - matches[1].rm_so;
                    if(group_length < MAX_GROUP_LENGTH) {
                        strncpy(group, http_data + matches[1].rm_so, sizeof(group));
                        group[group_length] = '\0';
                    }
                    else
                        fprintf(stderr, "Matched group is too long\n");
                }
                else
                    fprintf(stderr, "No match found for group\n");
            }
            else
                fprintf(stderr, "No match found for regex\n");
        }
    }
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

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

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
        memset(group, 0, sizeof(group));
        parse_packet(data, ret);
    }
    if (strncmp(netfilter_host, group, sizeof(netfilter_host)) == 0)
        id = 0;

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    if(id == 0) {
        printf("[ The packet was blocked by netfilter. ]\n");
        printf("[ Your_URL : %s, netfilter_URL : %s ]\n", group, netfilter_host);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if(argc != 2) {
        usage();
        return -1;
    }

    netfilter_host = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

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

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

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
