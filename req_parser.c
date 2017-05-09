#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

static int htp__request_parse_start_(htparser * p);
static int htp__request_parse_host_(htparser * p, const char * data, size_t len);
static int htp__request_parse_port_(htparser * p, const char * data, size_t len);
static int htp__request_parse_path_(htparser * p, const char * data, size_t len);
static int htp__request_parse_args_(htparser * p, const char * data, size_t len);
static int htp__request_parse_header_key_(htparser * p, const char * data, size_t len);
static int htp__request_parse_header_val_(htparser * p, const char * data, size_t len);
static int htp__request_parse_hostname_(htparser * p, const char * data, size_t len);
static int htp__request_parse_headers_(htparser * p);
static int htp__request_parse_body_(htparser * p, const char * data, size_t len);
static int htp__request_parse_fini_(htparser * p);
static int htp__request_parse_chunk_new_(htparser * p);
static int htp__request_parse_chunk_fini_(htparser * p);
static int htp__request_parse_chunks_fini_(htparser * p);
static int htp__request_parse_headers_start_(htparser * p);

/**
 * @brief callback definitions for request processing from libhtparse
 */
static htparse_hooks request_psets = {
    .on_msg_begin       = htp__request_parse_start_,
    .method             = NULL,
    .scheme             = NULL,
    .host               = htp__request_parse_host_,
    .port               = htp__request_parse_port_,
    .path               = htp__request_parse_path_,
    .args               = htp__request_parse_args_,
    .uri                = NULL,
    .on_hdrs_begin      = htp__request_parse_headers_start_,
    .hdr_key            = htp__request_parse_header_key_,
    .hdr_val            = htp__request_parse_header_val_,
    .hostname           = htp__request_parse_hostname_,
    .on_hdrs_complete   = htp__request_parse_headers_,
    .on_new_chunk       = htp__request_parse_chunk_new_,
    .on_chunk_complete  = htp__request_parse_chunk_fini_,
    .on_chunks_complete = htp__request_parse_chunks_fini_,
    .body               = htp__request_parse_body_,
    .on_msg_complete    = htp__request_parse_fini_
};

static int
htp__request_parse_start_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (evhtp_unlikely(c->type == evhtp_type_client))
    {
        return 0;
    }

    if (evhtp_unlikely(c->paused == 1))
    {
        return -1;
    }

    if (c->request)
    {
        if (c->request->finished == 1)
        {
            htp__request_free_(c->request);
        } else {
            return -1;
        }
    }

    if (evhtp_unlikely(!(c->request = htp__request_new_(c))))
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_headers_start_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->request->status = htp__hook_headers_start_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_header_key_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    char               * key_s;
    evhtp_header_t     * hdr;

    key_s      = malloc(len + 1);
    evhtp_alloc_assert(key_s);

    key_s[len] = '\0';
    memcpy(key_s, data, len);

    if ((hdr = evhtp_header_key_add(c->request->headers_in, key_s, 0)) == NULL)
    {
        c->request->status = EVHTP_RES_FATAL;

        return -1;
    }

    hdr->k_heaped = 1;

    return 0;
}

static int
htp__request_parse_header_val_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    char               * val_s;
    evhtp_header_t     * header;

    val_s      = malloc(len + 1);
    evhtp_alloc_assert(val_s);

    val_s[len] = '\0';
    memcpy(val_s, data, len);

    if ((header = evhtp_header_val_add(c->request->headers_in, val_s, 0)) == NULL)
    {
        evhtp_safe_free(val_s, free);
        c->request->status = EVHTP_RES_FATAL;

        return -1;
    }

    header->v_heaped = 1;

    if ((c->request->status = htp__hook_header_(c->request, header)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_hostname_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    struct evhtp_      * evhtp;
    struct evhtp_      * evhtp_vhost;

#ifndef EVHTP_DISABLE_SSL
    if (c->vhost_via_sni == 1 && c->ssl != NULL)
    {
        /* use the SNI set hostname instead of the header hostname */
        const char * host;

        host = SSL_get_servername(c->ssl, TLSEXT_NAMETYPE_host_name);

        if ((c->request->status = htp__hook_hostname_(c->request, host)) != EVHTP_RES_OK)
        {
            return -1;
        }

        return 0;
    }
#endif

    evhtp = c->htp;

    /* since this is called after htp__request_parse_path_(), which already
     * setup callbacks for the URI, we must now attempt to find callbacks which
     * are specific to this host.
     */
    htp__lock_(evhtp);
    {
        if ((evhtp_vhost = htp__request_find_vhost_(evhtp, data)))
        {
            htp__lock_(evhtp_vhost);
            {
                /* if we found a match for the host, we must set the htp
                 * variables for both the connection and the request.
                 */
                c->htp          = evhtp_vhost;
                c->request->htp = evhtp_vhost;

                htp__request_set_callbacks_(c->request);
            }
            htp__unlock_(evhtp_vhost);
        }
    }
    htp__unlock_(evhtp);

    if ((c->request->status = htp__hook_hostname_(c->request, data)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
} /* htp__request_parse_hostname_ */

static int
htp__request_parse_host_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_authority_t  * authority;

    if (htp__require_uri_(c) != 0)
    {
        return -1;
    }

    authority           = c->request->uri->authority;
    authority->hostname = malloc(len + 1);

    if (!authority->hostname)
    {
        c->request->status = EVHTP_RES_FATAL;

        return -1;
    }

    memcpy(authority->hostname, data, len);
    authority->hostname[len] = '\0';

    return 0;
}

static int
htp__request_parse_port_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_authority_t  * authority;
    char               * endptr;
    unsigned long        port;

    if (htp__require_uri_(c) != 0)
    {
        return -1;
    }

    authority = c->request->uri->authority;
    port      = strtoul(data, &endptr, 10);

    if (endptr - data != len || port > 65535)
    {
        c->request->status = EVHTP_RES_FATAL;

        return -1;
    }

    authority->port = port;

    return 0;
}

static int
htp__request_parse_path_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_path_t       * path;

    if (htp__require_uri_(c) != 0)
    {
        return -1;
    }

    if (evhtp_unlikely(!(path = htp__path_new_(data, len))))
    {
        c->request->status = EVHTP_RES_FATAL;

        return -1;
    }

    c->request->uri->path   = path;
    c->request->uri->scheme = htparser_get_scheme(p);
    c->request->method      = htparser_get_method(p);

    htp__lock_(c->htp);
    {
        htp__request_set_callbacks_(c->request);
    }
    htp__unlock_(c->htp);

    if ((c->request->status = htp__hook_path_(c->request, path)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}     /* htp__request_parse_path_ */

static int
htp__request_parse_headers_(htparser * p)
{
    evhtp_connection_t * c;

    c = htparser_get_userdata(p);
    evhtp_assert(c != NULL);

    /* XXX proto should be set with htparsers on_hdrs_begin hook */
    c->request->keepalive = htparser_should_keep_alive(p);
    c->request->proto     = htp__protocol_(htparser_get_major(p), htparser_get_minor(p));
    c->request->status    = htp__hook_headers_(c->request, c->request->headers_in);

    if (c->request->status != EVHTP_RES_OK)
    {
        return -1;
    }

    if (c->type == evhtp_type_server && c->htp->disable_100_cont == 0)
    {
        /* only send a 100 continue response if it hasn't been disabled via
         * evhtp_disable_100_continue.
         */
        if (!evhtp_header_find(c->request->headers_in, "Expect"))
        {
            return 0;
        }

        evbuffer_add_printf(bufferevent_get_output(c->bev),
                            "HTTP/%c.%c 100 Continue\r\n\r\n",
                            evhtp_modp_uchartoa(htparser_get_major(p)),
                            evhtp_modp_uchartoa(htparser_get_minor(p)));
    }

    return 0;
}

static int
htp__request_parse_body_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c   = htparser_get_userdata(p);
    evbuf_t            * buf;
    int                  res = 0;

    if (c->max_body_size > 0 && c->body_bytes_read + len >= c->max_body_size)
    {
        c->error           = 1;
        c->request->status = EVHTP_RES_DATA_TOO_LONG;

        return -1;
    }

    buf = c->scratch_buf;
    evhtp_assert(buf != NULL);


    evbuffer_add(buf, data, len);

    if ((c->request->status = htp__hook_body_(c->request, buf)) != EVHTP_RES_OK)
    {
        res = -1;
    }

    if (evbuffer_get_length(buf))
    {
        evbuffer_add_buffer(c->request->buffer_in, buf);
    }

    evbuffer_drain(buf, -1);

    c->body_bytes_read += len;

    return res;
}

static int
htp__request_parse_chunk_new_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->request->status = htp__hook_chunk_new_(c->request,
                                                   htparser_get_content_length(p))) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_chunk_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->request->status = htp__hook_chunk_fini_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_chunks_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->request->status = htp__hook_chunks_fini_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

/**
 * @brief determines if the request body contains the query arguments.
 *        if the query is NULL and the contenet length of the body has never
 *        been drained, and the content-type is x-www-form-urlencoded, the
 *        function returns 1
 *
 * @param req
 *
 * @return 1 if evhtp can use the body as the query arguments, 0 otherwise.
 */
static int
htp__should_parse_query_body_(evhtp_request_t * req)
{
    const char * content_type;

    if (req == NULL)
    {
        return 0;
    }

    if (req->uri == NULL || req->uri->query != NULL)
    {
        return 0;
    }

    if (evhtp_request_content_len(req) == 0)
    {
        return 0;
    }

    if (evhtp_request_content_len(req) !=
        evbuffer_get_length(req->buffer_in))
    {
        return 0;
    }

    content_type = evhtp_kv_find(req->headers_in, "content-type");

    if (content_type == NULL)
    {
        return 0;
    }

    if (strncasecmp(content_type, "application/x-www-form-urlencoded", 33))
    {
        return 0;
    }

    return 1;
}

static int
htp__request_parse_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (c->paused == 1)
    {
        return -1;
    }

    /* check to see if we should use the body of the request as the query
     * arguments.
     */
    if (htp__should_parse_query_body_(c->request) == 1)
    {
        const char  * body;
        size_t        body_len;
        evhtp_uri_t * uri;
        evbuf_t     * buf_in;

        uri            = c->request->uri;
        buf_in         = c->request->buffer_in;

        body_len       = evbuffer_get_length(buf_in);
        body           = (const char *)evbuffer_pullup(buf_in, body_len);

        uri->query_raw = calloc(body_len + 1, 1);
        evhtp_alloc_assert(uri->query_raw);

        memcpy(uri->query_raw, body, body_len);

        uri->query     = evhtp_parse_query(body, body_len);
    }


    /*
     * XXX c->request should never be NULL, but we have found some path of
     * execution where this actually happens. We will check for now, but the bug
     * path needs to be tracked down.
     *
     */
    if (c->request && c->request->cb)
    {
        (c->request->cb)(c->request, c->request->cbarg);
    }

    if (c->paused == 1)
    {
        return -1;
    }

    return 0;
} /* htp__request_parse_fini_ */

static int
htp__request_parse_args_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c   = htparser_get_userdata(p);
    evhtp_uri_t        * uri = c->request->uri;
    const char         * fragment;
    int                  ignore_fragment;

    if (c->type == evhtp_type_client)
    {
        /* as a client, technically we should never get here, but just in case
         * we return a 0 to the parser to continue.
         */
        return 0;
    }


    /* if the parser flags has the IGNORE_FRAGMENTS bit set, skip
     * the fragment parsing
     */
    ignore_fragment = (c->htp->parser_flags &
                       EVHTP_PARSE_QUERY_FLAG_IGNORE_FRAGMENTS);


    if (!ignore_fragment && (fragment = memchr(data, '#', len)))
    {
        /* Separate fragment from query according to RFC 3986.
         *
         * XXX: not happy about using strchr stuff, maybe this functionality
         * is more apt as part of evhtp_parse_query()
         */

        ptrdiff_t frag_offset;

        frag_offset = fragment - data;

        if (frag_offset < len)
        {
            size_t fraglen;

            /* Skip '#'. */
            fragment              += 1;
            frag_offset           += 1;
            fraglen                = len - frag_offset;

            uri->fragment          = malloc(fraglen + 1);
            evhtp_alloc_assert(uri->fragment);

            memcpy(uri->fragment, fragment, fraglen);

            uri->fragment[fraglen] = '\0';
            len -= fraglen + 1; /* Skip '#' + fragment string. */
        }
    }

    uri->query = evhtp_parse_query_wflags(data, len, c->htp->parser_flags);

    if (evhtp_unlikely(!uri->query))
    {
        c->request->status = EVHTP_RES_ERROR;

        return -1;
    }

    uri->query_raw      = malloc(len + 1);
    evhtp_alloc_assert(uri->query_raw);

    memcpy(uri->query_raw, data, len);
    uri->query_raw[len] = '\0';

    return 0;
} /* htp__request_parse_args_ */

