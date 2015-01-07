/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.

 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.

 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * @file
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include "htp_private.h"

#include <endian.h>

/**
 * Determines protocol number from a textual representation (i.e., "HTTP/1.1"). This
 * function will only understand a properly formatted protocol information. It does
 * not try to be flexible.
 * 
 * @param[in] protocol
 * @return Protocol version or PROTOCOL_UNKNOWN.
 */
int htp_parse_protocol(bstr *protocol) {
    if (protocol == NULL) return HTP_PROTOCOL_INVALID;
    
    // TODO This function uses a very strict approach to parsing, whereas
    //      browsers will typically be more flexible, allowing whitespace
    //      before and after the forward slash, as well as allowing leading
    //      zeroes in the numbers. We should be able to parse such malformed
    //      content correctly (but emit a warning).
    if (bstr_len(protocol) == 8) {
        unsigned char *ptr = bstr_ptr(protocol);
        if ((ptr[0] == 'H') && (ptr[1] == 'T') && (ptr[2] == 'T') && (ptr[3] == 'P')
            && (ptr[4] == '/') && (ptr[6] == '.')) {
            // Check the version numbers
            if (ptr[5] == '0') {
                if (ptr[7] == '9') {
                    return HTP_PROTOCOL_0_9;
                }
            } else if (ptr[5] == '1') {
                if (ptr[7] == '0') {
                    return HTP_PROTOCOL_1_0;
                } else if (ptr[7] == '1') {
                    return HTP_PROTOCOL_1_1;
                }
            }
        }
    }

    return HTP_PROTOCOL_INVALID;
}

/**
 * Determines the numerical value of a response status given as a string.
 *
 * @param[in] status
 * @return Status code on success, or -1 on error.
 */
int htp_parse_status(bstr *status) {
    return htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(status), bstr_len(status), 10);
}

/**
 * Parses Digest Authorization request header.
 *
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authorization_digest(htp_connp_t *connp, htp_header_t *auth_header) {    
    // Extract the username
    int i = bstr_index_of_c(auth_header->value, "username=");
    if (i == -1) return HTP_DECLINED;

    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t pos = i + 9;

    // Ignore whitespace
    while ((pos < len) && (isspace((int) data[pos]))) pos++;   

    if (data[pos] != '"') return HTP_DECLINED;

    connp->in_tx->request_auth.basic_digest = calloc(1, sizeof(struct htp_auth_params_basic_digest));
    if (connp->in_tx->request_auth.basic_digest == NULL) return HTP_ERROR;

    return htp_extract_quoted_string_as_bstr(
        data + pos, len - pos, &(connp->in_tx->request_auth.basic_digest->username), NULL);
}

/**
 * Parses Basic Authorization request header.
 * 
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authorization_basic(htp_connp_t *connp, htp_header_t *auth_header) {
    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t pos = 5;

    // Ignore whitespace
    while ((pos < len) && (isspace((int) data[pos]))) pos++;
    if (pos == len) return HTP_DECLINED;

    // Decode base64-encoded data
    bstr *decoded = htp_base64_decode_mem(data + pos, len - pos);
    if (decoded == NULL) return HTP_ERROR;

    // Now extract the username and password
    int i = bstr_index_of_c(decoded, ":");
    if (i == -1) {
        bstr_free(decoded);    
        return HTP_DECLINED;
    }

    connp->in_tx->request_auth.basic_digest = calloc(1, sizeof(struct htp_auth_params_basic_digest));
    if (connp->in_tx->request_auth.basic_digest == NULL) return HTP_ERROR;

    connp->in_tx->request_auth.basic_digest->username = bstr_dup_ex(decoded, 0, i);
    if (connp->in_tx->request_auth.basic_digest->username == NULL) {
        bstr_free(decoded);
        return HTP_ERROR;
    }

    connp->in_tx->request_auth.basic_digest->password = bstr_dup_ex(decoded, i + 1, bstr_len(decoded) - i - 1);
    if (connp->in_tx->request_auth.basic_digest->password == NULL) {
        bstr_free(decoded);
        return HTP_ERROR;
    }

    bstr_free(decoded);

    return HTP_OK;
}


/**
 * NTLM header blocks.
 */
static char htp_ntlm_type1_header[] =
    {'N',  'T',  'L',  'M',
     'S',  'S',  'P',  0x00,
     0x01, 0x00, 0x00, 0x00};

static char htp_ntlm_type2_header[] =
    {'N',  'T',  'L',  'M',
     'S',  'S',  'P',  0x00,
     0x02, 0x00, 0x00, 0x00};

static char htp_ntlm_type3_header[] =
    {'N',  'T',  'L',  'M',
     'S',  'S',  'P',  0x00,
     0x03, 0x00, 0x00, 0x00};

/**
 * Validates and isolates a parameter in a message.
 *
 * @param[in] data
 * @param[in] data_len
 * @param[in] param_len_off
 * @param[in] expected_param_off
 * @param[out] param
 */
static int htp_ntlm_extract_param(unsigned char *data, size_t data_len,
        uint16_t param_len_off, bstr* param) {
    uint16_t param_len =
        data[param_len_off + 0] + (data[param_len_off + 1] << 8);
    uint16_t param_off =
        data[param_len_off + 4] + (data[param_len_off + 5] << 8);

    // does the host name overflow the buffer
    if ((param_off + param_len) > data_len) return HTP_DECLINED;

    bstr_adjust_realptr(param, data + param_off);
    bstr_adjust_len(param, param_len);

    return HTP_OK;
}

/**
 * Parses NTLM Authorization request header.
 *
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authorization_ntlm(htp_connp_t *connp, htp_header_t *auth_header) {
    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t off = 4;

    connp->in_tx->request_auth.ntlm = calloc(1, sizeof(struct htp_auth_params_ntlm));
    if (connp->in_tx->request_auth.ntlm == NULL) return HTP_ERROR;

    connp->in_tx->request_auth.ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE_UNKNOWN;

    // Ignore whitespace
    while ((off < len) && (isspace((int) data[off]))) off++;
    if (off == len) return HTP_DECLINED;

    // less than any encoded NTLM header block
    if ((len - off) < 9) return HTP_DECLINED;

    connp->in_tx->request_auth.ntlm->raw_message = bstr_dup_mem(data + off, len - off);
    if (connp->in_tx->request_auth.ntlm->raw_message == NULL) {
        return HTP_ERROR;
    }

    // Decode base64-encoded data
    bstr *decoded = htp_base64_decode_mem(data + off, len - off);
    if (decoded == NULL) return HTP_ERROR;

    data = bstr_ptr(decoded);
    len = bstr_len(decoded);

    // less than any NTLM header
    if (len < 12) {
      bstr_free(decoded);
      return HTP_DECLINED;
    }

    if (bstr_begins_with_mem_nocase(decoded, htp_ntlm_type1_header, 12)) {
        if (len < 32) {
            // message is not even long enough to hold zero length params
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr hostname;
        if (htp_ntlm_extract_param(data, len, 24, &hostname) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr domainname;
        if (htp_ntlm_extract_param(data, len, 16, &domainname) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        connp->in_tx->request_auth.ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE1;

        connp->in_tx->request_auth.ntlm->message.type1.hostname = bstr_dup(&hostname);
        if (connp->in_tx->request_auth.ntlm->message.type1.hostname == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }

        connp->in_tx->request_auth.ntlm->message.type1.domainname = bstr_dup(&domainname);
        if (connp->in_tx->request_auth.ntlm->message.type1.domainname == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }
    } else if (bstr_begins_with_mem_nocase(decoded, htp_ntlm_type3_header, 12)) {
        if (len < 64) {
            // message is not even long enough to hold zero length params
            bstr_free(decoded);
            return HTP_DECLINED;
        }
        bstr domainname;
        if (htp_ntlm_extract_param(data, len, 28, &domainname) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr username;
        if (htp_ntlm_extract_param(data, len, 36, &username) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr hostname;
        if (htp_ntlm_extract_param(data, len, 44, &hostname) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr lm_response;
        if (htp_ntlm_extract_param(data, len, 12, &lm_response) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        bstr nt_response;
        if (htp_ntlm_extract_param(data, len, 20, &nt_response) != HTP_OK) {
            bstr_free(decoded);
            return HTP_DECLINED;
        }

        connp->in_tx->request_auth.ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE3;

        connp->in_tx->request_auth.ntlm->message.type3.domainname = bstr_dup(&domainname);
        if (connp->in_tx->request_auth.ntlm->message.type3.domainname == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }

        connp->in_tx->request_auth.ntlm->message.type3.username = bstr_dup(&username);
        if (connp->in_tx->request_auth.ntlm->message.type3.username == NULL) {
        bstr_free(decoded);
        return HTP_ERROR;
    }
    
        connp->in_tx->request_auth.ntlm->message.type3.hostname = bstr_dup(&hostname);
        if (connp->in_tx->request_auth.ntlm->message.type3.hostname == NULL) {
        bstr_free(decoded);
        return HTP_ERROR;
    }

        connp->in_tx->request_auth.ntlm->message.type3.lm_response = bstr_dup(&lm_response);
        if (connp->in_tx->request_auth.ntlm->message.type3.lm_response == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }

        connp->in_tx->request_auth.ntlm->message.type3.nt_response = bstr_dup(&nt_response);
        if (connp->in_tx->request_auth.ntlm->message.type3.nt_response == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }
    } else {
      // unexpected message
      bstr_free(decoded);
      return HTP_DECLINED;
    }

    bstr_free(decoded);

    return HTP_OK;
}

/**
 * Parses Authorization request header.
 *
 * @param[in] connp
 */
int htp_parse_authorization(htp_connp_t *connp) {
    htp_header_t *auth_header = NULL;
    if (((auth_header = htp_table_get_c(connp->in_tx->request_headers, "authorization")) == NULL) &&
        ((auth_header = htp_table_get_c(connp->in_tx->request_headers, "proxy-authorization")) == NULL)) {
        connp->in_tx->request_auth_type = HTP_AUTH_NONE;
        return HTP_OK;
    }

    // TODO Need a flag to raise when failing to parse authentication headers.

    if (bstr_begins_with_c_nocase(auth_header->value, "basic")) {
        // Basic authentication
        connp->in_tx->request_auth_type = HTP_AUTH_BASIC;
        return htp_parse_authorization_basic(connp, auth_header);
    } else if (bstr_begins_with_c_nocase(auth_header->value, "digest")) {
        // Digest authentication
        connp->in_tx->request_auth_type = HTP_AUTH_DIGEST;
        return htp_parse_authorization_digest(connp, auth_header);
    } else if (bstr_begins_with_c_nocase(auth_header->value, "ntlm")) {
        // NTLM authentication
        connp->in_tx->request_auth_type = HTP_AUTH_NTLM;
        return htp_parse_authorization_ntlm(connp, auth_header);
    } else {
        // Unrecognized authentication method
        connp->in_tx->request_auth_type = HTP_AUTH_UNRECOGNIZED;        
    }

    return HTP_OK;
}

/**
 * Parses NTLM Authenticate response header.
 *
 * @param[in] connp
 * @param[in] auth_header
 */
int htp_parse_authenticate_ntlm(htp_connp_t *connp, htp_header_t *auth_header) {
    unsigned char *data = bstr_ptr(auth_header->value);
    size_t len = bstr_len(auth_header->value);
    size_t off = 4;

    connp->out_tx->response_auth_ntlm = calloc(1, sizeof(struct htp_auth_params_ntlm));
    if (connp->out_tx->response_auth_ntlm == NULL) return HTP_ERROR;

    connp->out_tx->request_auth.ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE_UNKNOWN;

    // Ignore whitespace
    while ((off < len) && (isspace((int) data[off]))) off++;
    if (off == len) {
        // Initial response that indicates support for NTLM authentication
        connp->out_tx->request_auth.ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE_INITIAL;
        return HTP_OK;
    }

    // less than any encoded NTLM header block
    if ((len - off) < 9) return HTP_DECLINED;

    connp->out_tx->response_auth_ntlm->raw_message = bstr_dup_mem(data + off, len - off);
    if (connp->out_tx->response_auth_ntlm->raw_message == NULL) {
        return HTP_ERROR;
    }

    // Decode base64-encoded data
    bstr *decoded = htp_base64_decode_mem(data + off, len - off);
    if (decoded == NULL) return HTP_ERROR;

    data = bstr_ptr(decoded);
    len = bstr_len(decoded);

    // less than any NTLM header
    if (len < 12) return HTP_DECLINED;

    if (bstr_begins_with_mem_nocase(decoded, htp_ntlm_type2_header, 12)) {
        if (len < 32) {
            // message is not long enough to hold a nonce block
            bstr_free(decoded);
            return HTP_DECLINED;
        }
        connp->out_tx->response_auth_ntlm->type = HTP_AUTH_NTLM_MESSAGE_TYPE2;

        connp->out_tx->response_auth_ntlm->message.type2.nonce = bstr_dup_mem(data + 24, 8);
        if (connp->out_tx->response_auth_ntlm->message.type2.nonce == NULL) {
            bstr_free(decoded);
            return HTP_ERROR;
        }
    } else {
      // unexpected message
      bstr_free(decoded);
      return HTP_DECLINED;
    }

    bstr_free(decoded);

    return HTP_OK;
}

/**
 * Parses Authenticate response header.
 *
 * @param[in] connp
 */
int htp_parse_authenticate(htp_connp_t *connp) {
    htp_header_t *auth_header = htp_table_get_c(connp->out_tx->response_headers, "authenticate");
    if (auth_header == NULL) {
        auth_header = htp_table_get_c(connp->out_tx->response_headers, "proxy-authenticate");
        if (auth_header == NULL) {
            connp->out_tx->response_auth_type = HTP_AUTH_NONE;
            return HTP_OK;
        }
    }

    // TODO Need a flag to raise when failing to parse authentication headers.

    if (bstr_begins_with_c_nocase(auth_header->value, "ntlm")) {
        // NTLM authentication
        connp->out_tx->response_auth_type = HTP_AUTH_NTLM;
        return htp_parse_authenticate_ntlm(connp, auth_header);
    } else {
        // Unrecognized authentication method
        connp->out_tx->response_auth_type = HTP_AUTH_UNRECOGNIZED;
    }

    return HTP_OK;
}
