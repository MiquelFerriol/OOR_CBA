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
#include "../lib/timers_utils.h"
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


typedef struct _timer_bc_argument {
	lisp_addr_t *seid;
    mcache_entry_t *mce;
    lisp_addr_t *ra;
    lisp_addr_t *deid;
} timer_bc_argument;

static int
build_and_send_encap_map_request(lisp_mr_t *mr, lisp_addr_t *seid,
        mcache_entry_t *mce, uint64_t nonce, lisp_addr_t* drloc, lisp_addr_t* deid)
{

    uconn_t uc;
    mapping_t *m = NULL;
    lisp_addr_t *srloc;
    glist_t *rlocs = NULL;
    lbuf_t *b = NULL;
    void *mr_hdr = NULL;


    OOR_LOG(LDBG_1, "deid: %s", lisp_addr_to_char(deid));

    /* BUILD Map-Request */

    // Rlocs to be used as ITR of the map req.
    rlocs = ctrl_default_rlocs(mr->super.ctrl);
    OOR_LOG(LDBG_1, "locators for req: %s", laddr_list_to_char(rlocs));
    OOR_LOG(LDBG_1, "lisp_msg_mreq_create");
    b = lisp_msg_mreq_create(seid, rlocs, deid);
    if (b == NULL) {
        OOR_LOG(LDBG_1, "build_and_send_encap_map_request: Couldn't create map request message");
        glist_destroy(rlocs);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "lisp_msg_hdr");
    mr_hdr = lisp_msg_hdr(b);
    MREQ_NONCE(mr_hdr) = nonce;
    OOR_LOG(LDBG_1, "%s, itr-rlocs:%s, src-eid: %s, req-eid: %s",
            lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
            lisp_addr_to_char(seid), lisp_addr_to_char(deid));

    OOR_LOG(LDBG_1, "glist_destroy");
    glist_destroy(rlocs);


    /* Encapsulate message and send it to the map resolver */

    OOR_LOG(LDBG_1, "lisp_msg_encap");
    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, seid, deid);

    srloc = NULL;
    if (!drloc){
        lisp_msg_destroy(b);
        return (BAD);
    }

    OOR_LOG(LDBG_1, "uconn_init");
    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);

    OOR_LOG(LDBG_1, "send_msg");
    send_msg(&mr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}


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

    bc_hdr_msg* hdr = (bc_hdr_msg*)lbuf_data(b);

    uint64_t nonce = combine(ntohl(hdr->upper_nonce),ntohl(hdr->lower_nonce));

    OOR_LOG(LDBG_1,"SIZE: %" PRIu32, b->size);

    OOR_LOG(LDBG_1,"NONCE: %"PRIu64, nonce);

    OOR_LOG(LDBG_1,"FLAG: %u",hdr->flag);


    lbuf_pull(b,sizeof(bc_hdr_msg));

	if(hdr->flag == 0){
		uint8_t* count = (uint8_t*) lbuf_data(b);
		OOR_LOG(LDBG_1,"Count %u",*count);
	    lbuf_pull(b,sizeof(uint8_t));
	    lisp_addr_t* drloc = lisp_addr_new();
	    lisp_msg_parse_addr(b,drloc);
	    OOR_LOG(LDBG_1, " First addr: %s", lisp_addr_to_char(drloc));

	    OOR_LOG(LDBG_1,"Getting timer arguments");

	    OOR_LOG(LDBG_1,"Getting timer");
		nonces_list_t *nonces = htable_nonces_lookup(nonces_ht,nonce);

		if(nonces == NULL){
			OOR_LOG(LDBG_1,"There is no timer associated with nonce %"PRIu64, nonce);
			return BAD;
		}
		timer_bc_argument *timer_arg = (timer_bc_argument *)oor_timer_cb_argument(nonces->timer);
		mcache_entry_t *mce = timer_arg->mce;
		lisp_addr_t *seid = timer_arg->seid;
		lisp_addr_t *deid = timer_arg->deid;
		lisp_mr_t *mr = oor_timer_owner(nonces->timer);
		build_and_send_encap_map_request(mr,seid,mce,nonce,drloc,deid);
		stop_timer_from_obj(mce,nonces->timer,ptrs_to_timers_ht,nonces_ht);

	}
	else if(hdr->flag == 1){
		mapping_t *map = mapping_new();
		locator_t *probed;
		lisp_msg_parse_mapping_record(b,map,&probed);


		lbuf_t *mrep = lisp_msg_create(LISP_MAP_REPLY);
		lisp_msg_put_mapping(mrep, map, NULL);
		void* mrep_hdr = lisp_msg_hdr(mrep);
		MREP_NONCE(mrep_hdr) = nonce;


		OOR_LOG(LDBG_1,"Getting timer");
		nonces_list_t *nonces = htable_nonces_lookup(nonces_ht,nonce);

		if(nonces == NULL){
			OOR_LOG(LDBG_1,"There is no timer associated with nonce %"PRIu64, nonce);
			return BAD;
		}

		OOR_LOG(LDBG_1,"Getting timer arguments");
		timer_bc_argument *timer_arg = (timer_bc_argument *)oor_timer_cb_argument(nonces->timer);
		OOR_LOG(LDBG_1,"ITR_LOCS");

		uconn_t uc;

		uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, timer_arg->ra);

		lisp_mr_t *mr = oor_timer_owner(nonces->timer);
		send_msg(&mr->super,mrep,&uc);

	    lisp_msg_destroy(mrep);

		mcache_entry_t *mce = timer_arg->mce;
		stop_timer_from_obj(mce,nonces->timer,ptrs_to_timers_ht,nonces_ht);
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

timer_bc_argument *
timer_bc_argument_new_init(lisp_addr_t *seid, mcache_entry_t *mce, lisp_addr_t *ra, lisp_addr_t *deid)
{
	timer_bc_argument *timer_arg = xmalloc(sizeof(timer_bc_argument));
    timer_arg->seid = lisp_addr_clone(seid);
    timer_arg->mce = mce;
    timer_arg->ra = lisp_addr_clone(ra);
    timer_arg->deid = lisp_addr_clone(deid);

    return(timer_arg);
}

void
timer_bc_arg_free(timer_bc_argument * timer_arg)
{
    lisp_addr_del(timer_arg->seid);
    free(timer_arg);
}

static int
send_map_request_bc(oor_timer_t *timer)
{
    OOR_LOG(LDBG_1, "Requested time out. Deleting timers...");

	timer_bc_argument *timer_arg = (timer_bc_argument *)oor_timer_cb_argument(timer);
	mcache_entry_t *mce = timer_arg->mce;
	stop_timer_from_obj(mce,timer,ptrs_to_timers_ht,nonces_ht);
    return GOOD;
}

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


	OOR_LOG(LDBG_1,"glist_first_data");
	void *data = glist_first_data(itr_rlocs);
	OOR_LOG(LDBG_1,"lisp_addr_t");
	lisp_addr_t* ra = (lisp_addr_t*)(data);
    OOR_LOG(LDBG_1, " ITR-LOC %s", lisp_addr_to_char(ra));

    /* Process records and build Map-Reply */

    if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
        goto err;
    }
    OOR_LOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));
    OOR_LOG(LDBG_1, " src-eid: %s", lisp_addr_to_char(seid));


    mapping_t * m = mapping_new_init(deid);
	locator_t *probed;
    lisp_msg_parse_mapping_record(buf,m,&probed);
    mcache_entry_t *mce = mcache_entry_new();
    mcache_entry_init(mce, m);

    int ret;
    timer_bc_argument *timer_arg;

    if(lisp_addr_lafi(seid) == LM_AFI_NO_ADDR){
		OOR_LOG(LDBG_1, "SourceEID not set. Getting new...");
    	seid = lisp_addr_clone(&int_uc->ra);
    }

    timer_arg = timer_bc_argument_new_init(seid,mce,ra,deid);
    oor_timer_t *timer;

    timer = oor_timer_with_nonce_new(BLOCKCHAIN_TIMER,mr,send_map_request_bc,
    		timer_arg,(oor_timer_del_cb_arg_fn)timer_bc_arg_free);

    htable_ptrs_timers_add(ptrs_to_timers_ht,mce,timer);

    nonces_list_t *nonces_list = oor_timer_nonces(timer);
    htable_nonces_insert(nonces_ht, MREQ_NONCE(mreq_hdr), nonces_list);
    oor_timer_start(timer, 5);

	lbuf_t *sb;
	sb = lisp_msg_create_buf();

	OOR_LOG(LDBG_1, "NONCE: %"PRIu64, MREQ_NONCE(mreq_hdr));

	void *hdr = lisp_msg_put_bc_hdr(sb,MREQ_NONCE(mreq_hdr),lisp_addr_get_iana_afi(deid));

	OOR_LOG(LDBG_1, "AFI: %u", ((bc_hdr_t*)lbuf_data(sb))->afi);

	lbuf_put(sb,&(deid->ip.addr),16);

	lisp_addr_t src_addr;
	if (lisp_addr_ippref_from_char(API_ADDR,&src_addr) != GOOD){
		OOR_LOG(LDBG_1, "Error while address creation");
		return BAD;
	}

	send_datagram_packet(mr->blockchain_write_api_socket, lbuf_data(sb), lbuf_size(sb), &src_addr, WR_PORT);

	OOR_LOG(LDBG_1, "Requesting MR to BlockChain API");

    //if (ret == BAD){
    //	mc_entry_start_expiration_timer2(xtr, mce, 10);
	//}
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
