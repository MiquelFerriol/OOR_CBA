/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "lisp_mr.h"
#include "../lib/sockets.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"
#include "../liblisp/lisp_messages.h"
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define RD_PORT 16002
#define WR_PORT 16001
#define API_ADDR "127.0.0.1/32"
#define BUFF_LEN 1024
static oor_ctrl_dev_t *mr_ctrl_alloc();
static int mr_ctrl_construct(oor_ctrl_dev_t *dev);
static void mr_ctrl_destruct(oor_ctrl_dev_t *dev);
static void mr_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void mr_ctrl_run(oor_ctrl_dev_t *dev);
static int mr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc);
int mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state);
int mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status);
int mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
fwd_info_t *mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
fwd_info_t *mr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
static inline lisp_mr_t * lisp_mr_cast(oor_ctrl_dev_t *dev);
static int mr_recv_map_request(lisp_mr_t *mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
int process_blockchain_api_msg(struct sock *sl);

/* implementation of ctrl base functions */
ctrl_dev_class_t mr_ctrl_class = {
        .alloc = mr_ctrl_alloc,
        .construct = mr_ctrl_construct,
        .dealloc = mr_ctrl_dealloc,
        .destruct = mr_ctrl_destruct,
        .run = mr_ctrl_run,
        .recv_msg = mr_recv_msg,
        .if_link_update = mr_if_link_update,
        .if_addr_update = mr_if_addr_update,
        .route_update = mr_route_update,
        .get_fwd_entry = mr_get_forwarding_entry
};

struct packet {
    uint32_t a;
    uint32_t b;
    unsigned char c;
    char* d;
};

static oor_ctrl_dev_t *
mr_ctrl_alloc()
{
    lisp_mr_t *mr;
    mr = xzalloc(sizeof(lisp_mr_t));
    return(&mr->super);
}

static int
mr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_mr_t * mr = lisp_mr_cast(dev);
    lisp_addr_t src_addr;

    if (lisp_addr_ippref_from_char(API_ADDR,&src_addr) != GOOD){
		OOR_LOG(LDBG_1, "Error while address creation");
	}

    mr->blockchain_read_api_socket = open_udp_datagram_socket(AF_INET);
    if(mr->blockchain_read_api_socket == ERR_SOCKET){
        OOR_LOG(LDBG_1,"Error while creating server socket");   
        goto err;
    }
    bind_socket(mr->blockchain_read_api_socket, AF_INET, &src_addr, RD_PORT);

    //TODO function called when received message from
    sockmstr_register_read_listener(smaster, process_blockchain_api_msg, NULL,mr->blockchain_read_api_socket);
    OOR_LOG(LDBG_1,"Server socket created");   
    
    
    mr->blockchain_write_api_socket = open_udp_datagram_socket(AF_INET);
    if(mr->blockchain_write_api_socket == -1){
        OOR_LOG(LDBG_1,"Error while creating client socket");   
        goto err;
    }
    OOR_LOG(LDBG_1,"Client socket created");   
    
    return(GOOD);
    
err:
    OOR_LOG(LDBG_2,"MR: The API client couldn't be initialized.\n");
    return (BAD);
}

uint64_t combine(uint32_t high, uint32_t low) { return (((uint64_t) high) << 32) | ((uint64_t) low); }

typedef struct _bc_hdr_msg {
#ifdef LITTLE_ENDIANS
	uint32_t upper_nonce;
	uint32_t lower_nonce;
	uint8_t flag; //If 0 MS else MR
#else
	uint8_t flag;
	uint32_t upper_nonce;
	uint32_t lower_nonce;
#endif
} __attribute__ ((__packed__)) bc_hdr_msg;

//TODO To process replys of blockchain process
int
process_blockchain_api_msg(struct sock *sl)
{
    lbuf_t* b;

    b = lisp_msg_create_buf();

    if (sock_recv(sl->fd, b) != GOOD) {
        OOR_LOG(LDBG_1, "Couldn't read socket. Discarding packet!");
        lbuf_del(b);
        return (BAD);
    }

    OOR_LOG(LDBG_1, "Received response from BlockChain API");


    //uint64_t nonce = (uint64_t)(ntohl((uint32_t)lbuf_pull(b,sizeof(uint32_t)))<<32);

    /*OOR_LOG(LDBG_1,"Received message from blockchain api:");
    uint32_t upper_nonce = ntohl((uint32_t)lbuf_data(b));
    lbuf_pull(b,sizeof(uint32_t));
    OOR_LOG(LDBG_1,"upper_nonce: %x",upper_nonce);
    uint32_t lower_nonce = ntohl((uint32_t)lbuf_data(b));
    lbuf_pull(b,sizeof(uint32_t));
    OOR_LOG(LDBG_1,"NONCE 1: %"PRIu64, combine(upper_nonce,lower_nonce));*/

    bc_hdr_msg* hdr = (bc_hdr_msg*)lbuf_data(b);

    uint64_t nonce = combine(ntohl(hdr->upper_nonce),ntohl(hdr->lower_nonce));

    OOR_LOG(LDBG_1,"SIZE1: %" PRIu32, b->size);

    OOR_LOG(LDBG_1,"NONCE1: %"PRIu64, nonce);

    OOR_LOG(LDBG_1,"FLAG1: %u",hdr->flag);


    lbuf_pull(b,sizeof(bc_hdr_msg));

	/*hdr = (bc_hdr_msg*)lbuf_data(b);

	nonce = combine(ntohl(hdr->upper_nonce),ntohl(hdr->lower_nonce));

    OOR_LOG(LDBG_1,"SIZE2: %" PRIu32, b->size);

	OOR_LOG(LDBG_1,"NONCE2: %"PRIu64, nonce);

	OOR_LOG(LDBG_1,"FLAG2: %u",hdr->flag);*/

	if(hdr->flag == 0){
		OOR_LOG(LDBG_1,"Received MapServers");
	}
	else if(hdr->flag == 1){
		lbuf_t* mrep = lisp_msg_create(LISP_MAP_REPLY);

	    /*if (!map_loc_e) {
	        OOR_LOG(LDBG_1,"EID %s not locally configured!",
	                lisp_addr_to_char(deid));
	        goto err;
	    }*/
	    /*map = map_local_entry_mapping(map_loc_e);
	    lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
	            ? &int_uc->la: NULL);*/
		/*
		void *mrep_hdr = lisp_msg_hdr(mrep);
	    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
	    MREP_NONCE(mrep_hdr) = nonce;
		 */
	    /* SEND MAP-REPLY */
	    /*if (map_reply_fill_uconn(&xtr->tr, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
	        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
	        goto err;
	    }*/
	    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
	    //send_msg(&xtr->super, mrep, &send_uc);
	}
	else{
	    OOR_LOG(LDBG_1,"Invalid flag: %u",hdr->flag);
	    lbuf_del(b);
	    return (BAD);
	}


    lbuf_del(b);
    
    return (GOOD);
}

static void
mr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    OOR_LOG(LDBG_1,"Map Resolver device destroyed");
}

static void
mr_ctrl_dealloc(oor_ctrl_dev_t *dev) {
    lisp_mr_t *mr = lisp_mr_cast(dev);
    free(mr);
    OOR_LOG(LDBG_1, "Freed Map Resolver ...");
}

static void
mr_ctrl_run(oor_ctrl_dev_t *dev)
{
    OOR_LOG(LDBG_1, "\nStarting OOR as a Map Resolver ...\n");


}


static int
mr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = 0;
    lisp_msg_type_e type;
    lisp_mr_t *mr = lisp_mr_cast(dev);
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;
    packet_tuple_t inner_tuple;
    uint16_t src_port;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {

        if (lisp_msg_ecm_decap(msg, &src_port) != GOOD) {
            return (BAD);
        }
        type = lisp_msg_type(msg);
        pkt_parse_inner_5_tuple(msg, &inner_tuple);
        uconn_init(&aux_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
        ext_uc = uc;
        int_uc = &aux_uc;
        ecm_hdr = lbuf_lisp_hdr(msg);
    }else{
        int_uc = uc;
    }

    switch (type) {
    case LISP_MAP_REQUEST:
        if (!ecm_hdr){
            OOR_LOG(LDBG_1, "MR: Received a not Encap Map Request. Discarding!");
            ret = BAD;
            break;
        }
        ret = mr_recv_map_request(mr, msg, ecm_hdr, int_uc, ext_uc);
        ret = GOOD;
        break;
    case LISP_MAP_REPLY:
    case LISP_MAP_REGISTER:
    case LISP_MAP_NOTIFY:
    case LISP_INFO_NAT:
    default:
        OOR_LOG(LDBG_3, "Map-Resolver: Received control message with type %d."
                " Discarding!", type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        OOR_LOG(LDBG_1,"MR: Failed to process LISP control message");
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "MR: Completed processing of LISP control message");
        return (ret);
    }
}

int
mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state)
{
    return (GOOD);
}
int
mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    return (GOOD);
}
int
mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return (GOOD);
}

fwd_info_t *
mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

fwd_info_t *
mr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

static inline lisp_mr_t *
lisp_mr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &mr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_mr_t, super));
}

/*************************** PROCESS MESSAGES ********************************/

static int
mr_recv_map_request(lisp_mr_t *mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lisp_addr_t *seid = NULL;
    lisp_addr_t *deid = NULL;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr = NULL;
    lbuf_t  b;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }


    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        OOR_LOG(LDBG_1, "MR can not receive Map Request Probe. Discarding!");
        goto err;
    }

    if (MREQ_SMR(mreq_hdr)) {
        OOR_LOG(LDBG_1, "MR can not receive SMR Map Request. Discarding!");
        goto err;
    }

    if (MREQ_REC_COUNT(mreq_hdr) > 1){
        OOR_LOG(LDBG_1, "This version of MR only supports messages with one record. Discarding!");
        goto err;
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    /* Process records and build Map-Reply */

    if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
        goto err;
    }
    OOR_LOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));



    // TODO : Send message to the Blockchain API requesting this EID. Don't forget to
    // use the nonce -> MREQ_NONCE(mreq_hdr)

    lbuf_t *sb;    
    sb = lisp_msg_create_buf();

    /*OOR_LOG(LDBG_1, "Adding NONCE");
    OOR_LOG(LDBG_1, "Adding afi");*/
    OOR_LOG(LDBG_1, "NONCE: %"PRIu64, MREQ_NONCE(mreq_hdr));
    void *hdr = lisp_msg_put_bc_hdr(sb,MREQ_NONCE(mreq_hdr),lisp_addr_get_iana_afi(deid));
    OOR_LOG(LDBG_1, "AFI: %u", ((bc_hdr_t*)lbuf_data(sb))->afi);

    //lbuf_push(sb,lisp_addr_get_iana_afi(deid),sizeof(uint16_t));
    //OOR_LOG(LDBG_1, "Adding ip");
    lisp_msg_put_addr(sb,deid);
    

    lisp_addr_t src_addr;
    if (lisp_addr_ippref_from_char(API_ADDR,&src_addr) != GOOD){
    	OOR_LOG(LDBG_1, "Error while address creation");
    }
/*
    OOR_LOG(LDBG_1,"Sending message to blockchain API: %x",lbuf_data(sb));
    OOR_LOG(LDBG_1,"Sending message to blockchain API: %02X",lbuf_data(sb));
    OOR_LOG(LDBG_1, "NONCE: %x", ((bc_hdr_t*)lbuf_data(sb))->nonce);
    OOR_LOG(LDBG_1, "AFI: %02X", ((bc_hdr_t*)lbuf_data(sb))->afi);*/
    send_datagram_packet(mr->blockchain_write_api_socket, lbuf_data(sb), lbuf_size(sb), &src_addr, WR_PORT);

    OOR_LOG(LDBG_1, "Requesting MR to BlockChain API");

    
    //struct sockaddr_in si_other;
    /*char nonce[20];
    char afi[1];
    sprintf(nonce, "%"PRIu64, MREQ_NONCE(mreq_hdr));
    OOR_LOG(LDBG_1, "NONCE %s",nonce);
    sprintf (afi, "%u", lisp_addr_get_iana_afi(deid));
    OOR_LOG(LDBG_1, "AFI %s",afi);
    char* ip;
    if(lisp_addr_get_iana_afi(deid) == 1){
        char ip[8];
        struct in_addr ipv4data;
        inet_pton(AF_INET,  "192.168.0.1", &ipv4data);
        sprintf(ip,"%ld",ipv4data.s_addr);
        OOR_LOG(LDBG_1, "IPV4 %s",ip);
    }
    
    else{
        struct in6_addr ipv6data;
        inet_pton(AF_INET6,  lisp_addr_to_char(deid), &ipv6data);
        ip = ipv6data.s6_addr[0-15];
        OOR_LOG(LDBG_1, "IPV6 ");
        
    }*/
/*
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(WR_PORT);
    
    if (inet_aton("127.0.0.1", &si_other.sin_addr) == 0)
    { 
        OOR_LOG(LDBG_1, "inet_aton failed");
        goto err;
    }

    OOR_LOG(LDBG_1, "SENDING MSG");
    //send the message
    if (sendto(mr->blockchain_write_api_socket, &sb->data, sizeof sb->data , 0 , (struct sockaddr *) &si_other, sizeof(si_other))==-1){
        OOR_LOG(LDBG_1, "Error while sending message to blockchain");
        goto err;
    }
    OOR_LOG(LDBG_1, "MSG SEND");
    */



    /* Check the existence of the requested EID */
    // TODO: Example of how the mrep is created. This message should be created if
    // blockchain return a mapping instead of a set of MSs
//    mrep = lisp_msg_create(LISP_MAP_REPLY);
//    if (!map_loc_e) {
//        OOR_LOG(LDBG_1,"EID %s not locally configured!",
//                lisp_addr_to_char(deid));
//        goto err;
//    }
//    map = map_local_entry_mapping(map_loc_e);
//    lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
//            ? &int_uc->la: NULL);
//
//    mrep_hdr = lisp_msg_hdr(mrep);
//    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
//    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);
//
//    /* SEND MAP-REPLY */
//    if (map_reply_fill_uconn(&xtr->tr, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
//        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
//        goto err;
//    }
//    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
//    send_msg(&xtr->super, mrep, &send_uc);

done:
    glist_destroy(itr_rlocs);
    //lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    //lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(BAD);
}

