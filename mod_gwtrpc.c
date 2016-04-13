/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

/* This is an extension to allow GWT-RPC payload parsing.
 *
 * This module defines "GWTRPC" and can be enabled with a rule like this:
 *  SecAction "phase:1,pass,nolog,ctl:requestBodyProcessor=GWTRPC"
 *
 *
 * Author : Tin Duong
 *          tinduong@vnsecurity.net
 *          https://blog.tinduong.pw
*/


#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_optional.h"

#include "modsecurity.h"

#include "regex.h"

#define VALID_HEX(X) (((X >= '0')&&(X <= '9')) || ((X >= 'a')&&(X <= 'f')) || ((X >= 'A')&&(X <= 'F')))

static unsigned char *c2x(unsigned what, unsigned char *where);
static unsigned char x2c(unsigned char *what);
static apr_status_t modsecurity_request_body_end_raw(modsec_rec *msr, char **error_msg);
static char *_log_escape(apr_pool_t *p, const unsigned char *input, unsigned long int input_length, int escape_quotes, int escape_colon, int escape_re);
int parse_arguments(modsec_rec *msr, const char *s, apr_size_t inputlength, const char *origin, apr_table_t *arguments, int *invalid_count);
char *log_escape_ex(apr_pool_t *p, const char *text, unsigned long int text_length);
void  add_argument(modsec_rec *msr, apr_table_t *arguments, msc_arg *arg);


typedef struct gwtrpc_ctx {
    unsigned long    length;
} gwtrpc_ctx;


/**
 * This function will be invoked to initialize the processor.  This is
 * probably only needed for streaming parsers that must create a context.
 */
static int gwtrpc_init(modsec_rec *msr, char **error_msg) {
    if (error_msg == NULL) return -1;
    *error_msg = NULL;

    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, NULL, "mod_gwtrpc_parser: init()");

    msr->reqbody_processor_ctx = apr_pcalloc(msr->mp, sizeof(gwtrpc_ctx));
    if (msr->reqbody_processor_ctx == NULL) {
        /* Set error message and return -1 if unsuccessful */
        *error_msg = apr_pstrdup(msr->mp, "failed to create GWT-RPC request body processor context");
        return -1;
    }

    /* Return 1 on success */
    return 1;
}

/**
 * This function will be invoked whenever the ModSecurity has data to
 * be processed.  You probably at least need to increment the no_files
 * length, but otherwise this is only useful for a streaming parser.
 */
static int gwtrpc_process(modsec_rec *msr, const char *buf, unsigned int size, char **error_msg) {
    gwtrpc_ctx *ctx = (gwtrpc_ctx *)msr->reqbody_processor_ctx;

    if (error_msg == NULL) return -1;
    *error_msg = NULL;

    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, NULL, "mod_gwtrpc_parser: process()");

    /* Need to increment the no_files length if this is not an uploaded file.
     * Failing to do this will mess up some other limit checks.
     */
    msr->msc_reqbody_no_files_length += size;

    /* Check for an existing context and do something interesting
     * with the chunk of data we have been given.
     */
    if (ctx != NULL) {
        ctx->length += size;
    }

    /* Return 1 on success */
    return 1;
}

/**
 * This function is called to signal the parser that the request body is
 * complete. Here you should do any final parsing.  For non-streaming parsers
 * you can parse the data in msr->msc_reqbody_buffer of length
 * msr->msc_reqbody_length.  See modsecurity_request_body_end_urlencoded() in
 * msc_reqbody.c for an example of this.
 */
static int gwtrpc_complete(modsec_rec *msr, char **error_msg) {
    int invalid_count = 0;
    gwtrpc_ctx *ctx = (gwtrpc_ctx *)msr->reqbody_processor_ctx;

    if (error_msg == NULL) return -1;
    *error_msg = NULL;

    /* Create the raw buffer */
    if (modsecurity_request_body_end_raw(msr, error_msg) != 1) {
        return -1;
    }

    if (parse_arguments(msr, msr->msc_reqbody_buffer, msr->msc_reqbody_length, "BODY", msr->arguments, &invalid_count) < 0) {
        *error_msg = apr_pstrdup(msr->mp, "Initialisation: Error occurred while parsing BODY arguments.");
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, NULL, "mod_gwtrpc_parser: complete()");

    ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, NULL, "mod_gwtrpc_parser: request body length=%lu", ctx->length);

    /* Return 1 on success */
    return 1;
}

static int hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log, apr_pool_t *mp_temp) {

    void (*fn)(const char *name, void *fn_init, void *fn_process, void *fn_complete);

    /* Look for the registration function exported by ModSecurity. */
    fn = APR_RETRIEVE_OPTIONAL_FN(modsec_register_reqbody_processor);
    if (fn) {
        /* Use it to register our new request body parser functions under
         * the name "EXAMPLE".
         */
        fn("GWTRPC", (void *)gwtrpc_init, (void *)gwtrpc_process, (void *)gwtrpc_complete);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, NULL, "mod_gwtrpc_parser: Unable to find modsec_register_reqbody_processor.");
    }

    return OK;
}

/* This is a function to register another function to be called during
 * the Apache configuration process.
 */
static void register_hooks(apr_pool_t *p) {
    ap_hook_pre_config(hook_pre_config, NULL, NULL, APR_HOOK_LAST);
}

/**
 * Replace a bunch of chunks holding a request body with a single large chunk.
 */
static apr_status_t modsecurity_request_body_end_raw(modsec_rec *msr, char **error_msg) {
    msc_data_chunk **chunks, *one_chunk;
    char *d;
    int i, sofar;

    *error_msg = NULL;

    /* Allocate a buffer large enough to hold the request body. */

    if (msr->msc_reqbody_length + 1 == 0) {
        *error_msg = apr_psprintf(msr->mp, "Internal error, request body length will overflow: %u", msr->msc_reqbody_length);
        return -1;
    }

    msr->msc_reqbody_buffer = malloc(msr->msc_reqbody_length + 1);
    if (msr->msc_reqbody_buffer == NULL) {
        *error_msg = apr_psprintf(msr->mp, "Unable to allocate memory to hold request body. Asked for %u bytes.", msr->msc_reqbody_length + 1);
        return -1;
    }

    msr->msc_reqbody_buffer[msr->msc_reqbody_length] = '\0';

    /* Copy the data we keep in chunks into the new buffer. */

    sofar = 0;
    d = msr->msc_reqbody_buffer;
    chunks = (msc_data_chunk **)msr->msc_reqbody_chunks->elts;
    for(i = 0; i < msr->msc_reqbody_chunks->nelts; i++) {
        if (sofar + chunks[i]->length <= msr->msc_reqbody_length) {
            memcpy(d, chunks[i]->data, chunks[i]->length);
            d += chunks[i]->length;
            sofar += chunks[i]->length;
        } else {
            *error_msg = apr_psprintf(msr->mp, "Internal error, request body buffer overflow.");
            return -1;
        }
    }


    /* Now free the memory used by the chunks. */

    chunks = (msc_data_chunk **)msr->msc_reqbody_chunks->elts;
    for(i = 0; i < msr->msc_reqbody_chunks->nelts; i++) {
        free(chunks[i]->data);
        chunks[i]->data = NULL;
    }

    /* Create a new array with only one chunk in it. */

    msr->msc_reqbody_chunks = apr_array_make(msr->msc_reqbody_mp, 2, sizeof(msc_data_chunk *));
    if (msr->msc_reqbody_chunks == NULL) {
        *error_msg = apr_pstrdup(msr->mp, "Failed to create structure to hold request body.");
        return -1;
    }

    one_chunk = (msc_data_chunk *)apr_pcalloc(msr->msc_reqbody_mp, sizeof(msc_data_chunk));
    one_chunk->data = msr->msc_reqbody_buffer;
    one_chunk->length = msr->msc_reqbody_length;
    one_chunk->is_permanent = 1;
    *(const msc_data_chunk **)apr_array_push(msr->msc_reqbody_chunks) = one_chunk;

    if(msr->txcfg->reqbody_limit > 0 && msr->txcfg->reqbody_limit < msr->msc_reqbody_length)    {
        msr->msc_reqbody_length = msr->txcfg->reqbody_limit;
    }

    return 1;
}

/**
 * This is a function to convert GWT-RPC payload into form-urlencoded format.
 * Since GWT-RPC can serialize almost everything of Java(including custom
 * objects) and C can not reconstruct these objects, we can not completely
 * convert it into C objects, only values will be processed, but that's all
 * Mod Security needs.
 *
 * The result looks like : args[]=VALUE1&args[]=VALUE2&args[]=VALUE3&....
 *
 * There is no official document for GWT-RPC payload format. This module is
 * only implemented and tested for GWT-RPC version 7.
 * 
 */

int parse_arguments(modsec_rec *msr, const char *s, apr_size_t inputlength, const char *origin, apr_table_t *arguments, int *invalid_count) {
    msc_arg *arg;
    apr_size_t i;
    int num_args, flags, reti, offset, val_len, changed;
    char *value = NULL, *buff = NULL, *delim = "|";
    regex_t regex;

    if (s == NULL) return -1;
    if (inputlength == 0) return 1;


    i = 0;
    offset = 0;
    *invalid_count = 0;

    /* Regular expression to determine type */
    reti = regcomp(&regex, "^[a-zA-Z0-9._$]+[^.]/[0-9]+$", REG_EXTENDED);

    /* Duplicate raw GWT-RPC payload */
    buff = strdup(s);
    
    /* Skip first value which is a version number */
    value = strtok(buff, delim);
    if (value == NULL) return -1;
    offset += strlen(value) + 1;

    /* Flags value */
    value = strtok(NULL, delim);
    if (value == NULL) return -1;
    flags = atoi(value);
    offset += strlen(value) + 1;

    /* Number of value in string table */
    value = strtok(NULL, delim);
    if (value == NULL) return -1;
    num_args = atoi(value);
    offset += strlen(value) + 1;

    i = 0;
    while (i < 3) {
        /* First three values are servlet url, strong name and token (optional) */
        if ((i < 2) || (flags == 2)) {
            value = strtok(NULL, delim);
            if (value == NULL) return -1;
            offset += strlen(value) + 1;
            num_args--;
        }
        i++;
    }

    i = 0;
    while (i < num_args) {
        /* Fetch a string from string table */
        value = strtok(NULL, delim);
        if (value == NULL) {
            return -1;
        }

        val_len = strlen(value);

        /* Check that the string is a value or a data type */
        reti = regexec(&regex, value, 0, NULL, 0);
        if (reti) { /* If it is not a data type */
            /* An argument struct */
            arg = (msc_arg *)apr_pcalloc(msr->mp, sizeof(msc_arg));
            arg->origin = origin;

            arg->name_len = 6;
            arg->name = apr_pstrmemdup(msr->mp, "args[]", 6);
            arg->value_origin_offset = offset;
            arg->value_origin_len = val_len;
            arg->value_len = urldecode_nonstrict_inplace_ex((unsigned char *)value, arg->value_origin_len, invalid_count, &changed);
            arg->value = apr_pstrmemdup(msr->mp, value, arg->value_len);

            add_argument(msr, arguments, arg);
        }

        offset += val_len + 1;
        
        /* Next token */
        i++;
    }

    free(buff);

    return 1;

}



void add_argument(modsec_rec *msr, apr_table_t *arguments, msc_arg *arg) {
    /* I can not reuse msr_log. Anyway it does not affect to processing
    if (msr->txcfg->debuglog_level >= 5) {
        msr_log(msr, 5, "Adding request argument (%s): name \"%s\", value \"%s\"",
                arg->origin, log_escape_ex(msr->mp, arg->name, arg->name_len),
                log_escape_ex(msr->mp, arg->value, arg->value_len));
    }
    */

    apr_table_addn(arguments, log_escape_nq_ex(msr->mp, arg->name, arg->name_len), (void *)arg);
}


char *log_escape_ex(apr_pool_t *mp, const char *text, unsigned long int text_length) {
    return _log_escape(mp, (const unsigned char *)text, text_length, 1, 0, 0);
}

char *log_escape_nq_ex(apr_pool_t *mp, const char *text, unsigned long int text_length) {
    return _log_escape(mp, (const unsigned char *)text, text_length, 0, 0, 0);
}

/**
 * Transform input into a form safe for logging.
 */

char *_log_escape(apr_pool_t *mp, const unsigned char *input, unsigned long int input_len, int escape_quotes, int escape_colon, int escape_re) {
    unsigned char *d = NULL;
    char *ret = NULL;
    unsigned long int i;

    if (input == NULL) return NULL;

    ret = apr_palloc(mp, input_len * 4 + 1);
    if (ret == NULL) return NULL;
    d = (unsigned char *)ret;

    i = 0;
    while(i < input_len) {
        switch(input[i]) {
            case ':' :
                if (escape_colon) {
                    *d++ = '\\';
                    *d++ = ':';
                } else {
                    *d++ = input[i];
                }
                break;
            case '"' :
                if (escape_quotes) {
                    *d++ = '\\';
                    *d++ = '"';
                } else {
                    *d++ = input[i];
                }
                break;
            case '+' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '+';
                } else {
                    *d++ = input[i];
                }
                break;
            case '.' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '.';
                } else {
                    *d++ = input[i];
                }
                break;
            case ']' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = ']';
                } else {
                    *d++ = input[i];
                }
                break;
            case '[' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '[';
                } else {
                    *d++ = input[i];
                }
                break;
            case '(' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '(';
                } else {
                    *d++ = input[i];
                }
                break;
            case ')' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = ')';
                } else {
                    *d++ = input[i];
                }
                break;
            case '?' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '?';
                } else {
                    *d++ = input[i];
                }
                break;
            case '/' :
                if (escape_re) {
                    *d++ = '\\';
                    *d++ = '/';
                } else {
                    *d++ = input[i];
                }
                break;
            case '\b' :
                *d++ = '\\';
                *d++ = 'b';
                break;
            case '\n' :
                *d++ = '\\';
                *d++ = 'n';
                break;
            case '\r' :
                *d++ = '\\';
                *d++ = 'r';
                break;
            case '\t' :
                *d++ = '\\';
                *d++ = 't';
                break;
            case '\v' :
                *d++ = '\\';
                *d++ = 'v';
                break;
            case '\\' :
                *d++ = '\\';
                *d++ = '\\';
                break;
            default :
                if ((input[i] <= 0x1f)||(input[i] >= 0x7f)) {
                    *d++ = '\\';
                    *d++ = 'x';
                    c2x(input[i], d);
                    d += 2;
                } else {
                    *d++ = input[i];
                }
                break;
        }

        i++;
    }

    *d = 0;

    return ret;
}

/**
 * Converts a single byte into its hexadecimal representation.
 * Will overwrite two bytes at the destination.
 */
static unsigned char *c2x(unsigned what, unsigned char *where) {
    static const char c2x_table[] = "0123456789abcdef";

    what = what & 0xff;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0x0f];

    return where;
}

/**
 *
 * IMP1 Assumes NUL-terminated
 */
int urldecode_nonstrict_inplace_ex(unsigned char *input, long int input_len, int *invalid_count, int *changed) {
    unsigned char *d = (unsigned char *)input;
    long int i, count;

    *changed = 0;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '%') {
            /* Character is a percent sign. */

            /* Are there enough bytes available? */
            if (i + 2 < input_len) {
                char c1 = input[i + 1];
                char c2 = input[i + 2];

                if (VALID_HEX(c1) && VALID_HEX(c2)) {
                    /* Valid encoding - decode it. */
                    *d++ = x2c(&input[i + 1]);
                    count++;
                    i += 3;
                    *changed = 1;
                } else {
                    /* Not a valid encoding, skip this % */
                    *d++ = input[i++];
                    count ++;
                    (*invalid_count)++;
                }
            } else {
                /* Not enough bytes available, copy the raw bytes. */
                *d++ = input[i++];
                count ++;
                (*invalid_count)++;
            }
        } else {
            /* Character is not a percent sign. */
            if (input[i] == '+') {
                *d++ = ' ';
                *changed = 1;
            } else {
                *d++ = input[i];
            }
            count++;
            i++;
        }
    }

    *d = '\0';

    return count;
}

/**
 * Converts a byte given as its hexadecimal representation
 * into a proper byte. Handles uppercase and lowercase letters
 * but does not check for overflows.
 */
static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA gwtrpc_parser_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    register_hooks         /* register hooks                      */
};
