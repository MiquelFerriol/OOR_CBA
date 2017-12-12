
/*
 * oor_pkt_miss.c - skeleton vpp-api-test plug-in 
 *
 * Copyright (c) <current-year> <your-organization>
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
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vnet/fib/fib_types.h>
#include <vnet/ip/format.h>
#include <vppinfra/error.h>

#include <arpa/inet.h>

#define __plugin_msg_base oor_pkt_miss_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <oor_pkt_miss/oor_pkt_miss_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} oor_pkt_miss_test_main_t;

oor_pkt_miss_test_main_t oor_pkt_miss_test_main;

#define foreach_standard_reply_retval_handler   \
_(oor_pkt_miss_enable_disable_reply)            \
_(oor_pkt_miss_native_route_reply)              \
_(oor_pkt_miss_drop_route_reply)                \

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = oor_pkt_miss_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _



/********************** API REPLY HANDLER ***********************************/

static void
vl_api_oor_pkt_miss_get_default_route_reply_t_handler(vl_api_oor_pkt_miss_get_default_route_reply_t * mp)
{

    vat_main_t * vam = oor_pkt_miss_test_main.vat_main;
    i32 retval = ntohl (mp->retval);
    char ip_addr[INET6_ADDRSTRLEN];

    if (0 <= retval)
    {
        if (mp->is_ipv6){
            if (mp->has_gateway){
                inet_ntop(AF_INET6,&(mp->address),ip_addr,INET6_ADDRSTRLEN);
                fformat (vam->ofp, "IPv6 default gw: %s\n", ip_addr );
            }else{
                fformat (vam->ofp, "IPv6 default gw: --\n");
            }
        }else{
            if (mp->has_gateway){
                fformat (vam->ofp, "IPv4 default gw: %U\n",format_ip4_address, &(mp->address));
            }else{
                fformat (vam->ofp, "IPv4 default gw: --\n");
            }
        }
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(OOR_PKT_MISS_ENABLE_DISABLE_REPLY, oor_pkt_miss_enable_disable_reply) \
_(OOR_PKT_MISS_NATIVE_ROUTE_REPLY, oor_pkt_miss_native_route_reply)     \
_(OOR_PKT_MISS_DROP_ROUTE_REPLY, oor_pkt_miss_drop_route_reply)         \
_(OOR_PKT_MISS_GET_DEFAULT_ROUTE_REPLY, oor_pkt_miss_get_default_route_reply)


static int api_oor_pkt_miss_enable_disable (vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    int enable_disable = 1;
    u8 *host_if_name = NULL;
    vl_api_oor_pkt_miss_enable_disable_t * mp;
    int ret;


    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "disable"))
            enable_disable = 0;
        else if (unformat (input, "%s", &host_if_name))
            ;
        else
            break;
    }
    unformat_free (input);

    if (host_if_name == NULL){
        errmsg ("missing interface name\n");
        return -99;
    }

    /* Construct the API message */
    M(OOR_PKT_MISS_ENABLE_DISABLE, mp);
    memcpy(mp->host_if_name,host_if_name,strlen((char *)host_if_name));
    mp->enable_disable = enable_disable;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W(ret);

    return (ret);
}

static int api_oor_pkt_miss_native_route (vat_main_t * vam)
{
    vl_api_oor_pkt_miss_native_route_t * mp;
    unformat_input_t * input = vam->input;
    int is_add = 1;
    ip4_address_t ip4_addr;
    ip6_address_t ip6_addr;
    u32 pref_len;
    u8 ipv4_set = 0;
    u8 ipv6_set = 0;
    int ret;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")){
            is_add = 0;
        }else if (unformat (input, "add")){
            is_add = 1;
        }else if (unformat (input, "%U/%d",unformat_ip4_address, &ip4_addr, &pref_len)){
            ipv4_set = 1;
        }else if (unformat (input, "%U/%d",unformat_ip6_address, &ip6_addr, &pref_len)){
            ipv6_set = 1;
        }else{
            break;
        }
    }
    if (!ipv4_set && !ipv6_set){
        clib_error_return (0, "expected ip4/ip6 destination address/length.");
        return -99;
    }

    /* Construct the API message */
    M(OOR_PKT_MISS_NATIVE_ROUTE, mp);
    mp->is_add = is_add;
    mp->is_ipv6 = ipv6_set;
    mp->mask_len = pref_len;
    if (mp->is_ipv6 != 1){
        clib_memcpy (mp->address, &ip4_addr, sizeof(ip4_addr));
    }else{
        clib_memcpy (mp->address, &ip6_addr, sizeof(ip6_addr));
    }

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W(ret);

    return(ret);
}


static int api_oor_pkt_miss_drop_route (vat_main_t * vam)
{
    vl_api_oor_pkt_miss_drop_route_t * mp;
    unformat_input_t * input = vam->input;
    int is_add = 1;
    ip4_address_t ip4_addr;
    ip6_address_t ip6_addr;
    u32 pref_len;
    u8 ipv4_set = 0;
    u8 ipv6_set = 0;
    u32 table_id = 0;
    int ret;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")){
            is_add = 0;
        }else if (unformat (input, "add")){
            is_add = 1;
        }else if (unformat (input, "%U/%d",unformat_ip4_address, &ip4_addr, &pref_len)){
            ipv4_set = 1;
        }else if (unformat (input, "%U/%d",unformat_ip6_address, &ip6_addr, &pref_len)){
            ipv6_set = 1;
        }else if (unformat (input, "table-id %d", &table_id)){
            table_id = 1;
        }else{
            break;
        }
    }

    if (!ipv4_set && !ipv6_set){
        clib_error_return (0, "expected ip4/ip6 destination address/length.");
        return -99;
    }



    /* Construct the API message */
    M(OOR_PKT_MISS_DROP_ROUTE, mp);
    mp->is_add = is_add;
    mp->is_ipv6 = ipv6_set;
    mp->mask_len = pref_len;
    if (mp->is_ipv6 != 1){
        clib_memcpy (mp->address, &ip4_addr, sizeof(ip4_addr));
    }else{
        clib_memcpy (mp->address, &ip6_addr, sizeof(ip6_addr));
    }
    mp->table_id = table_id;
    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W(ret);

    return (ret);
}

static int api_oor_pkt_miss_get_default_route (vat_main_t * vam)
{
    vl_api_oor_pkt_miss_get_default_route_t * mp;
    unformat_input_t * input = vam->input;
    int is_ipv6 = 0;
    int ret;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "ipv6")){
            is_ipv6 = 1;
        }else if (unformat (input, "ipv4")){
            is_ipv6 = 0;
        }else{
            break;
        }
    }
    /* Construct the API message */
    M(OOR_PKT_MISS_GET_DEFAULT_ROUTE, mp);
    mp->is_ipv6 = is_ipv6;
    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W(ret);

    return (ret);
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(oor_pkt_miss_enable_disable, "<intfc> [disable]")             \
_(oor_pkt_miss_native_route, "[add|del] <dst-ip-addr>/<width>") \
_(oor_pkt_miss_drop_route, "[add|del] <dst-ip-addr>/<width>")   \
_(oor_pkt_miss_get_default_route, "[ipv4|ipv6]")

static void
oor_pkt_miss_vat_api_hookup (vat_main_t *vam)
{
    oor_pkt_miss_test_main_t * sm __attribute__((unused)) = &oor_pkt_miss_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _    
    
    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  oor_pkt_miss_test_main_t * sm = &oor_pkt_miss_test_main;
  u8 * name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "oor_pkt_miss_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
      oor_pkt_miss_vat_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
