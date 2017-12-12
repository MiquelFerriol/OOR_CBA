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

#ifndef LBUF_H_
#define LBUF_H_

#include <stdint.h>
#include <stdio.h>

#include "../defs.h"
#include "../elibs/ovs/list.h"

#define LBUF_STACK_OFFSET 100

typedef enum lbuf_source {
    LBUF_MALLOC,
    LBUF_STACK
} lbuf_source_e;

struct lbuf {
    struct ovs_list list;      /* for queueing, to be implemented*/

    uint32_t allocated;         /* allocated size */
    uint32_t size;              /* size in-use */

    uint16_t eth;               /* Eth hds offset */
    uint16_t ip;                /* IP hdr offset */
    uint16_t udp;               /* UDP hdr offset */

    uint16_t lhdr;              /* lisp hdr offset */
    uint16_t l3;                /* (inner) l3 hdr offset */
    uint16_t l4;                /* (inner) l4 hdr offset */

    uint16_t lisp;              /* lisp payload offset */

    lbuf_source_e source;       /* source of memory allocated as 'base' */
    void *base;                 /* start of allocated space */
    void *data;                 /* start of in-use space */
};

typedef struct lbuf lbuf_t;

void lbuf_use(lbuf_t *, void *, uint32_t);
void lbuf_use_stack(lbuf_t *, void *, uint32_t);
void lbuf_init(lbuf_t *, uint32_t);
void lbuf_uninit(lbuf_t *);
lbuf_t *lbuf_new(uint32_t);
lbuf_t *lbuf_new_with_headroom(uint32_t, uint32_t);
lbuf_t *lbuf_clone(lbuf_t *);
void lbuf_del(lbuf_t *);


static inline void *lbuf_at(const lbuf_t *, uint32_t, uint32_t);
static inline void *lbuf_tail(const lbuf_t *);
static inline void *lbuf_end(const lbuf_t *);
static inline void *lbuf_data(const lbuf_t *);
static inline void *lbuf_base(const lbuf_t *);
static inline uint32_t lbuf_size(const lbuf_t *);
static inline void lbuf_set_size(lbuf_t *, uint32_t);

void *lbuf_put_uninit(lbuf_t *, uint32_t);
void *lbuf_put(lbuf_t *, void *, uint32_t);
void *lbuf_push_uninit(lbuf_t *, uint32_t);
void *lbuf_push(lbuf_t *, void *, uint32_t);
static inline void *lbuf_pull(lbuf_t *b, uint32_t);

void lbuf_reserve(lbuf_t *b, uint32_t size);
lbuf_t *lbuf_clone(lbuf_t *b);

void lbuf_prealloc_tailroom(lbuf_t *b, uint32_t);
void lbuf_prealloc_headroom(lbuf_t *b, uint32_t);

static inline void lbuf_set_base(lbuf_t *, void *);
static inline void lbuf_set_data(lbuf_t *, void *);

static inline void lbuf_reset_eth(lbuf_t *b);
static inline void *lbuf_eth(lbuf_t *b);
static inline void lbuf_reset_ip(lbuf_t *b);
static inline void *lbuf_ip(lbuf_t *b);
int lbuf_point_to_ip(lbuf_t *b);
static inline void lbuf_reset_udp(lbuf_t *b);
static inline void *lbuf_udp(lbuf_t *b);
int lbuf_point_to_udp(lbuf_t *b);
static inline void lbuf_reset_l3(lbuf_t *b);
static inline void *lbuf_l3(lbuf_t *b);
int lbuf_point_to_l3(lbuf_t *b);
static inline void lbuf_reset_l4(lbuf_t *b);
static inline void *lbuf_l4(lbuf_t *b);
int lbuf_point_to_l4(lbuf_t *b);
static inline void lbuf_reset_lisp(lbuf_t *b);
static inline void *lbuf_lisp(lbuf_t*);
int lbuf_point_to_lisp(lbuf_t *b);
static inline void lbuf_reset_lisp_hdr(lbuf_t *b);
static inline void *lbuf_lisp_hdr(lbuf_t*);
int lbuf_point_to_lisp_hdr(lbuf_t *b);

static inline void
lbuf_set_base(lbuf_t *b, void *bs)
{
    b->base = bs;
}

static inline void
lbuf_set_data(lbuf_t *b, void *dt)
{
    b->data = dt;
}

static inline void *
lbuf_at(const lbuf_t *b, uint32_t offset, uint32_t size)
{
    return offset + size <= lbuf_size(b) ? (char *)lbuf_data(b) + offset : NULL;
}

static inline void *
lbuf_tail(const lbuf_t *b)
{
    return (char *)lbuf_data(b) + lbuf_size(b);
}

static inline void *
lbuf_end(const lbuf_t *b)
{
    return (char *)lbuf_base(b) + b->allocated;
}

static inline uint32_t
lbuf_headroom(const lbuf_t *b)
{
    return ((char *)lbuf_data(b) - (char *)lbuf_base(b));
}

static inline uint32_t
lbuf_tailroom(const lbuf_t *b)
{
    return (char *)lbuf_end(b) - (char *)lbuf_tail(b);
}

static inline void *
lbuf_data(const lbuf_t *b)
{
    return b->data;
}

static inline void *
lbuf_base(const lbuf_t *b)
{
    return b->base;
}

static inline uint32_t
lbuf_size(const lbuf_t *b)
{
    return b->size;
}

static inline void
lbuf_set_size(lbuf_t *b, uint32_t sz)
{
    b->size = sz;
}

/* moves 'data' pointer by 'size'. Returns first byte
 * of data removed */
static inline void *
lbuf_pull(lbuf_t *b, uint32_t size)
{
    if (size > b->size) {
        return NULL;
    }

    void *data = b->data;
    b->data = (uint8_t *) b->data + size;
    b->size -= size;
    return data;
}

static inline void
lbuf_reset_eth(lbuf_t *b)
{
    b->eth = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_eth(lbuf_t *b)
{
    return b->eth != UINT16_MAX ? (char *)lbuf_base(b) + b->eth : NULL;
}

static inline void
lbuf_reset_ip(lbuf_t *b)
{
    b->ip = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_ip(lbuf_t *b)
{
    return b->ip != UINT16_MAX ? (char *)lbuf_base(b) + b->ip : NULL;
}

static inline void
lbuf_reset_udp(lbuf_t *b)
{
    b->udp = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_udp(lbuf_t *b)
{
    return b->udp != UINT16_MAX ? (char *)lbuf_base(b) + b->udp : NULL;
}

static inline void
lbuf_reset_l3(lbuf_t *b)
{
    b->l3 = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_l3(lbuf_t *b)
{
    return b->l3 != UINT16_MAX ? (char *)lbuf_base(b) + b->l3 : NULL;
}

static inline void
lbuf_reset_l4(lbuf_t *b)
{
    b->l4 = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_l4(lbuf_t *b)
{
    return b->l4 != UINT16_MAX ? (char *)lbuf_base(b) + b->l4 : NULL;
}

static inline void
lbuf_reset_lisp(lbuf_t *b)
{
    b->lisp = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_lisp(lbuf_t *b)
{
    return b->lisp != UINT16_MAX ? (char *)lbuf_base(b) + b->lisp : NULL;
}

static inline void
lbuf_reset_lisp_hdr(lbuf_t *b)
{
    b->lhdr = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *
lbuf_lisp_hdr(lbuf_t *b)
{
    return b->lhdr != UINT16_MAX ? (char *)lbuf_base(b) + b->lhdr : NULL;
}

#endif /* LBUF_H_ */
