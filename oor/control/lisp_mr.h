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

#ifndef OOR_CONTROL_LISP_MR_H_
#define OOR_CONTROL_LISP_MR_H_

#include "oor_ctrl_device.h"

typedef struct _lisp_mr {
    oor_ctrl_dev_t super;    /* base "class" */
    int blockchain_read_api_socket;
    int blockchain_write_api_socket;
    
} lisp_mr_t;



#endif /* OOR_CONTROL_LISP_MR_H_ */
