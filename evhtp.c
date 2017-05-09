#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <inttypes.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef NO_SYS_UN
#include <sys/un.h>
#endif

#include <limits.h>
#include <event2/dns.h>

#include "evhtp-internal.h"
#include "evhtp_numtoa.h"
#include "evhtp.h"

struct htp__default_callbacks_ {
    evhtp_callback_cb    cb_fini;
    evhtp_pre_accept_cb  cb_pre_accept;
    evhtp_post_accept_cb cb_post_accept;

    void * cb_fini_arg;
    void * cb_pre_accept_arg;
    void * cb_post_accept_arg;
};

/**
 * @ingroup evhtp_core
 * @brief main structure containing all configuration information
 */
struct evhtp_ {
    struct evhtp_         * htp_parent;        /**< only when this is a vhost */
    struct event_base     * htp_evbase;        /**< the initialized event_base */
    struct evconnlistener * htp_server;        /**< the libevent listener struct */
    char                  * htp_server_name;   /**< the name included in Host: responses */
    void                  * htp_arg;           /**< user-defined struct evhtp_ specific arguments */
    int                     htp_htp_bev_flags; /**< bufferevent flags to use on bufferevent_*_socket_new() */
    ssize_t                 htp_max_body_size;
    unsigned                htp_max_keepalive_requests;
    #define EVHTP_CFLAG_DISABLE_100_CONT (1 << 1)
    #define EVHTP_CFLAG_ENABLE_REUSEPORT (1 << 2)
    #define EVHTP_CFLAG_ENABLE_NODELAY   (1 << 3)
    #define EVHTP_CFLAG_DEFER_ACCEPT     (1 << 4)
    uint8_t htp_flags;

    int htp_parser_flags;               /**< default query flags to alter 'strictness' (see EVHTP_PARSE_QUERY_FLAG_*) */

#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_ctx_t * ssl_ctx;          /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg_t * ssl_cfg;
#endif

#ifndef EVHTP_DISABLE_EVTHR
    evthr_pool_t    * thr_pool;         /**< connection threadpool */
    pthread_mutex_t * lock;             /**< parent lock for add/del cbs in threads */

    evhtp_thread_init_cb thread_init_cb;
    evhtp_thread_exit_cb thread_exit_cb;

    /* keep backwards compat because I'm dumb and didn't
     * make these structs private
     */
    #define thread_init_cbarg thread_cbarg
    void * thread_cbarg;
#endif
    evhtp_callbacks_t * callbacks;
    evhtp_defaults_t    defaults;

    struct timeval recv_timeo;
    struct timeval send_timeo;

    TAILQ_HEAD(, evhtp_alias_s) aliases;
    TAILQ_HEAD(, evhtp_s) vhosts;
    TAILQ_ENTRY(evhtp_s) next_vhost;
};


#ifdef EVHTP_DEBUG
static void
htp_log_connection(evhtp_connection_t * c)
{
    htp_log_debug("connection = %p\n", c);
    htp_log_debug("request = %p\n", c->request);
}

#endif




#if 0
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
#endif

static void htp__connection_readcb_(evbev_t * bev, void * arg);

static evhtp_connection_t * htp__connection_new_(struct evhtp_ * htp, evutil_socket_t sock, evhtp_type type);

static evhtp_uri_t * htp__uri_new_(void);
static void          htp__uri_free_(evhtp_uri_t * uri);

static evhtp_authority_t * htp__authority_new_(void);
static void                htp__authority_free_(evhtp_authority_t * authority);

static evhtp_path_t * htp__path_new_(const char * data, size_t len);
static void           htp__path_free_(evhtp_path_t * path);

static void htp__request_free_(evhtp_request_t *);


#ifndef EVHTP_DISABLE_EVTHR
#define htp__lock_(h)   do {             \
        if (h->lock)                     \
        {                                \
            pthread_mutex_lock(h->lock); \
        }                                \
} while (0)

#define htp__unlock_(h) do {               \
        if (h->lock)                       \
        {                                  \
            pthread_mutex_unlock(h->lock); \
        }                                  \
} while (0)
#else
#define htp__lock_(h)   do { \
} while (0)
#define htp__unlock_(h) do { \
} while (0)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

static const char *
status_code_to_str(evhtp_res code)
{
    switch (code) {
        case EVHTP_RES_200:
            return "OK";
        case EVHTP_RES_300:
            return "Redirect";
        case EVHTP_RES_400:
            return "Bad Request";
        case EVHTP_RES_NOTFOUND:
            return "Not Found";
        case EVHTP_RES_SERVERR:
            return "Internal Server Error";
        case EVHTP_RES_CONTINUE:
            return "Continue";
        case EVHTP_RES_FORBIDDEN:
            return "Forbidden";
        case EVHTP_RES_SWITCH_PROTO:
            return "Switching Protocols";
        case EVHTP_RES_MOVEDPERM:
            return "Moved Permanently";
        case EVHTP_RES_PROCESSING:
            return "Processing";
        case EVHTP_RES_URI_TOOLONG:
            return "URI Too Long";
        case EVHTP_RES_CREATED:
            return "Created";
        case EVHTP_RES_ACCEPTED:
            return "Accepted";
        case EVHTP_RES_NAUTHINFO:
            return "No Auth Info";
        case EVHTP_RES_NOCONTENT:
            return "No Content";
        case EVHTP_RES_RSTCONTENT:
            return "Reset Content";
        case EVHTP_RES_PARTIAL:
            return "Partial Content";
        case EVHTP_RES_MSTATUS:
            return "Multi-Status";
        case EVHTP_RES_IMUSED:
            return "IM Used";
        case EVHTP_RES_FOUND:
            return "Found";
        case EVHTP_RES_SEEOTHER:
            return "See Other";
        case EVHTP_RES_NOTMOD:
            return "Not Modified";
        case EVHTP_RES_USEPROXY:
            return "Use Proxy";
        case EVHTP_RES_SWITCHPROXY:
            return "Switch Proxy";
        case EVHTP_RES_TMPREDIR:
            return "Temporary Redirect";
        case EVHTP_RES_UNAUTH:
            return "Unauthorized";
        case EVHTP_RES_PAYREQ:
            return "Payment Required";
        case EVHTP_RES_METHNALLOWED:
            return "Not Allowed";
        case EVHTP_RES_NACCEPTABLE:
            return "Not Acceptable";
        case EVHTP_RES_PROXYAUTHREQ:
            return "Proxy Authentication Required";
        case EVHTP_RES_TIMEOUT:
            return "Request Timeout";
        case EVHTP_RES_CONFLICT:
            return "Conflict";
        case EVHTP_RES_GONE:
            return "Gone";
        case EVHTP_RES_LENREQ:
            return "Length Required";
        case EVHTP_RES_PRECONDFAIL:
            return "Precondition Failed";
        case EVHTP_RES_ENTOOLARGE:
            return "Entity Too Large";
        case EVHTP_RES_URITOOLARGE:
            return "Request-URI Too Long";
        case EVHTP_RES_UNSUPPORTED:
            return "Unsupported Media Type";
        case EVHTP_RES_RANGENOTSC:
            return "Requested Range Not Satisfiable";
        case EVHTP_RES_EXPECTFAIL:
            return "Expectation Failed";
        case EVHTP_RES_IAMATEAPOT:
            return "I'm a teapot";
        case EVHTP_RES_NOTIMPL:
            return "Not Implemented";
        case EVHTP_RES_BADGATEWAY:
            return "Bad Gateway";
        case EVHTP_RES_SERVUNAVAIL:
            return "Service Unavailable";
        case EVHTP_RES_GWTIMEOUT:
            return "Gateway Timeout";
        case EVHTP_RES_VERNSUPPORT:
            return "HTTP Version Not Supported";
        case EVHTP_RES_BWEXEED:
            return "Bandwidth Limit Exceeded";
    } /* switch */

    return "UNKNOWN";
}     /* status_code_to_str */

#ifndef EVHTP_DISABLE_SSL
static int session_id_context = 1;
#ifndef EVHTP_DISABLE_EVTHR
static int             ssl_num_locks;
static evhtp_mutex_t * ssl_locks;
static int             ssl_locks_initialized = 0;
#endif
#endif

/*
 * COMPAT FUNCTIONS
 */

#ifdef NO_STRNLEN
static size_t
strnlen(const char * s, size_t maxlen)
{
    const char * e;
    size_t       n;

    for (e = s, n = 0; *e && n < maxlen; e++, n++)
    {
        ;
    }

    return n;
}

#endif

#ifdef NO_STRNDUP
static char *
strndup(const char * s, size_t n)
{
    size_t len = strnlen(s, n);
    char * ret;

    if (len < n)
    {
        return strdup(s);
    }

    ret    = malloc(n + 1);
    ret[n] = '\0';

    memcpy(ret, s, n);

    return ret;
}

#endif

/*
 * PRIVATE FUNCTIONS
 */

/**
 * @brief a weak hash function
 *
 * @param str a null terminated string
 *
 * @return an unsigned integer hash of str
 */
static inline unsigned int
htp__quick_hash_(const char * str)
{
    unsigned int h = 0;

    for (; *str; str++)
    {
        h = 31 * h + *str;
    }

    return h;
}

/**
 *
 * @brief helper macro to determine if http version is HTTP/1.0
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.0, else 0
 */

#define htp__is_http_11_(_major, _minor) \
    (_major >= 1 && _minor >= 1)

/**
 * @brief helper function to determine if http version is HTTP/1.1
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.1, else 0
 */

#define htp__is_http_10_(_major, _minor) \
    (_major >= 1 && _minor <= 0)


/**
 * @brief returns the HTTP protocol version
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return EVHTP_PROTO_10 if HTTP/1.0, EVHTP_PROTO_11 if HTTP/1.1, otherwise
 *         EVHTP_PROTO_INVALID
 */
static inline evhtp_proto
htp__protocol_(const char major, const char minor)
{
    if (htp__is_http_10_(major, minor))
    {
        return EVHTP_PROTO_10;
    }

    if (htp__is_http_11_(major, minor))
    {
        return EVHTP_PROTO_11;
    }

    return EVHTP_PROTO_INVALID;
}

static int
htp__glob_match2_(const char * pattern, size_t plen,
                  const char * string, size_t str_len)
{
    while (plen)
    {
        switch (pattern[0]) {
            case '*':
                while (pattern[1] == '*')
                {
                    pattern++;
                    plen--;
                }

                if (plen == 1)
                {
                    return 1;     /* match */
                }

                while (str_len)
                {
                    if (htp__glob_match2_(pattern + 1, plen - 1,
                                          string, str_len))
                    {
                        return 1; /* match */
                    }

                    string++;
                    str_len--;
                }

                return 0;         /* no match */
            default:
                if (pattern[0] != string[0])
                {
                    return 0;     /* no match */
                }

                string++;
                str_len--;
                break;
        } /* switch */

        pattern++;
        plen--;

        if (str_len == 0)
        {
            while (*pattern == '*')
            {
                pattern++;
                plen--;
            }

            break;
        }
    }

    if (plen == 0 && str_len == 0)
    {
        return 1;
    }

    return 0;
} /* htp__glob_match2_ */

/**
 * @brief glob/wildcard type pattern matching.
 *
 * Note: This code was derived from redis's (v2.6) stringmatchlen() function.
 *
 * @param pattern
 * @param string
 *
 * @return
 */
static inline int
htp__glob_match_(const char * pattern, size_t pat_len, const char * string, size_t str_len)
{
    if (evhtp_unlikely(!pattern || !string))
    {
        return 0;
    }

    if (pat_len == 0)
    {
        pat_len = strlen(pattern);
    }

    if (str_len == 0)
    {
        str_len = strlen(string);
    }

    return htp__glob_match2_(pattern, pat_len, string, str_len);
} /* htp__glob_match_ */

static evhtp_callback_t *
htp__callback_find_(evhtp_callbacks_t * cbs,
                    const char        * path,
                    unsigned int      * start_offset,
                    unsigned int      * end_offset)
{
#ifndef EVHTP_DISABLE_REGEX
    regmatch_t pmatch[28];
#endif
    evhtp_callback_t * callback;

    if (evhtp_unlikely(cbs == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(callback, cbs, next)
    {
        switch (callback->type) {
            case evhtp_callback_type_hash:
                if (strcmp(callback->val.path, path) == 0)
                {
                    *start_offset = 0;
                    *end_offset   = (unsigned int)strlen(path);

                    return callback;
                }
                break;
#ifndef EVHTP_DISABLE_REGEX
            case evhtp_callback_type_regex:
                if (regexec(callback->val.regex, path, callback->val.regex->re_nsub + 1, pmatch, 0) == 0)
                {
                    *start_offset = pmatch[callback->val.regex->re_nsub].rm_so;
                    *end_offset   = pmatch[callback->val.regex->re_nsub].rm_eo;

                    return callback;
                }

                break;
#endif
            case evhtp_callback_type_glob:
            {
                size_t path_len = strlen(path);
                size_t glob_len = strlen(callback->val.glob);

                if (htp__glob_match_(callback->val.glob, glob_len,
                                     path, path_len) == 1)
                {
                    *start_offset = 0;
                    *end_offset   = (unsigned int)path_len;

                    return callback;
                }
            }
            default:
                break;
        } /* switch */
    }

    return NULL;
}         /* htp__callback_find_ */

/**
 * @brief Creates a new evhtp_request_t
 *
 * @param c
 *
 * @return evhtp_request_t structure on success, otherwise NULL
 */
static evhtp_request_t *
htp__request_new_(evhtp_connection_t * c)
{
    evhtp_request_t * req;
    uint8_t           error;

    if (evhtp_unlikely(!(req = calloc(sizeof(evhtp_request_t), 1))))
    {
        return NULL;
    }

    error       = 1;
    req->conn   = c;
    req->htp    = c ? c->htp : NULL;
    req->status = EVHTP_RES_OK;

    do {
        if (evhtp_unlikely(!(req->buffer_in = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->buffer_out = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_in = malloc(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_out = malloc(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        TAILQ_INIT(req->headers_in);
        TAILQ_INIT(req->headers_out);

        error = 0;
    } while (0);

    if (error == 0)
    {
        return req;
    }

    evhtp_safe_free(req, htp__request_free_);

    return req;
} /* htp__request_new_ */

/**
 * @brief frees all data in an evhtp_request_t along with calling finished hooks
 *
 * @param request the request structure
 */
static void
htp__request_free_(evhtp_request_t * request)
{
    if (evhtp_unlikely(request == NULL))
    {
        return;
    }

    htp__hook_request_fini_(request);

    evhtp_safe_free(request->uri, htp__uri_free_);
    evhtp_safe_free(request->headers_in, evhtp_kvs_free);
    evhtp_safe_free(request->headers_out, evhtp_kvs_free);

    if (request->conn && request->conn->request == request)
    {
        request->conn->request = NULL;
    }

    if (request->buffer_in != NULL)
    {
        evhtp_safe_free(request->buffer_in, evbuffer_free);
    }

    if (request->buffer_out != NULL)
    {
        evhtp_safe_free(request->buffer_out, evbuffer_free);
    }

    evhtp_safe_free(request->hooks, free);
    evhtp_safe_free(request, free);
}

/**
 * @brief create an overlay URI structure
 *
 * @return evhtp_uri_t
 */
static evhtp_uri_t *
htp__uri_new_(void)
{
    evhtp_uri_t * uri;

    if (!(uri = calloc(sizeof(evhtp_uri_t), 1)))
    {
        return NULL;
    }

    uri->authority = htp__authority_new_();

    if (!uri->authority)
    {
        htp__uri_free_(uri);

        return NULL;
    }

    return uri;
}

/**
 * @brief frees an authority structure
 *
 * @param authority evhtp_authority_t
 */
static void
htp__authority_free_(evhtp_authority_t * authority)
{
    if (authority == NULL)
    {
        return;
    }

    evhtp_safe_free(authority->username, free);
    evhtp_safe_free(authority->password, free);
    evhtp_safe_free(authority->hostname, free);

    evhtp_safe_free(authority, free);
}

/**
 * @brief create an authority structure
 *
 * @return evhtp_authority_t
 */
static evhtp_authority_t *
htp__authority_new_(void)
{
    evhtp_authority_t * authority;

    if (!(authority = calloc(1, sizeof(*authority))))
    {
        return NULL;
    }

    return authority;
}

/**
 * @brief frees an overlay URI structure
 *
 * @param uri evhtp_uri_t
 */
static void
htp__uri_free_(evhtp_uri_t * uri)
{
    if (evhtp_unlikely(uri == NULL))
    {
        return;
    }

    evhtp_safe_free(uri->query, evhtp_kvs_free);
    evhtp_safe_free(uri->path, htp__path_free_);
    evhtp_safe_free(uri->authority, htp__authority_free_);

    evhtp_safe_free(uri->fragment, free);
    evhtp_safe_free(uri->query_raw, free);

    evhtp_safe_free(uri, free);
}

/**
 * @brief parses the path and file from an input buffer
 *
 * @details in order to properly create a structure that can match
 *          both a path and a file, this will parse a string into
 *          what it considers a path, and a file.
 *
 * @details if for example the input was "/a/b/c", the parser will
 *          consider "/a/b/" as the path, and "c" as the file.
 *
 * @param data raw input data (assumes a /path/[file] structure)
 * @param len length of the input data
 *
 * @return evhtp_request_t * on success, NULL on error.
 */
static evhtp_path_t *
htp__path_new_(const char * data, size_t len)
{
    evhtp_path_t * req_path;
    const char   * data_end = (const char *)(data + len);
    char         * path     = NULL;
    char         * file     = NULL;

    req_path = calloc(sizeof(evhtp_path_t), 1);
    evhtp_alloc_assert(req_path);

    if (evhtp_unlikely(len == 0))
    {
        /*
         * odd situation here, no preceding "/", so just assume the path is "/"
         */
        path = strdup("/");
        evhtp_alloc_assert(path);
    } else if (*data != '/')
    {
        /* request like GET stupid HTTP/1.0, treat stupid as the file, and
         * assume the path is "/"
         */
        path = strdup("/");
        file = strndup(data, len);

        evhtp_alloc_assert(path);
        evhtp_alloc_assert(file);
    } else {
        if (data[len - 1] != '/')
        {
            /*
             * the last character in data is assumed to be a file, not the end of path
             * loop through the input data backwards until we find a "/"
             */
            size_t i;

            for (i = (len - 1); i != 0; i--)
            {
                if (data[i] == '/')
                {
                    /*
                     * we have found a "/" representing the start of the file,
                     * and the end of the path
                     */
                    size_t path_len;
                    size_t file_len;

                    path_len = (size_t)(&data[i] - data) + 1;
                    file_len = (size_t)(data_end - &data[i + 1]);

                    /* check for overflow */
                    if ((const char *)(data + path_len) > data_end)
                    {
                        evhtp_safe_free(req_path, free);

                        return NULL;
                    }

                    /* check for overflow */
                    if ((const char *)(&data[i + 1] + file_len) > data_end)
                    {
                        evhtp_safe_free(req_path, free);

                        return NULL;
                    }

                    path = strndup(data, path_len);
                    file = strndup(&data[i + 1], file_len);

                    evhtp_alloc_assert(path);
                    evhtp_alloc_assert(file);

                    break;
                }
            }

            if (i == 0 && data[i] == '/' && !file && !path)
            {
                /* drops here if the request is something like GET /foo */
                path = strdup("/");
                evhtp_alloc_assert(path);

                if (len > 1)
                {
                    file = strndup((const char *)(data + 1), len);
                    evhtp_alloc_assert(file);
                }
            }
        } else {
            /* the last character is a "/", thus the request is just a path */
            path = strndup(data, len);
            evhtp_alloc_assert(path);
        }
    }

    if (len != 0)
    {
        req_path->full = strndup(data, len);
    } else {
        req_path->full = strdup("/");
    }

    evhtp_alloc_assert(req_path->full);

    req_path->path = path;
    req_path->file = file;

    return req_path;
}     /* htp__path_new_ */

static void
htp__path_free_(evhtp_path_t * path)
{
    if (evhtp_unlikely(path == NULL))
    {
        return;
    }

    evhtp_safe_free(path->full, free);
    evhtp_safe_free(path->path, free);
    evhtp_safe_free(path->file, free);
    evhtp_safe_free(path->match_start, free);
    evhtp_safe_free(path->match_end, free);

    evhtp_safe_free(path, free);
}


static inline struct evhtp_ *
htp__request_find_vhost_(struct evhtp_ * evhtp, const char * name)
{
    struct evhtp_ * evhtp_vhost;
    evhtp_alias_t * evhtp_alias;

    TAILQ_FOREACH(evhtp_vhost, &evhtp->vhosts, next_vhost)
    {
        if (evhtp_unlikely(evhtp_vhost->server_name == NULL))
        {
            continue;
        }

        if (htp__glob_match_(evhtp_vhost->server_name, 0, name, 0) == 1)
        {
            return evhtp_vhost;
        }

        TAILQ_FOREACH(evhtp_alias, &evhtp_vhost->aliases, next)
        {
            if (evhtp_alias->alias == NULL)
            {
                continue;
            }

            if (htp__glob_match_(evhtp_alias->alias, 0, name, 0) == 1)
            {
                return evhtp_vhost;
            }
        }
    }

    return NULL;
}

static inline int
htp__request_set_callbacks_(evhtp_request_t * request)
{
    struct evhtp_      * evhtp;
    evhtp_connection_t * conn;
    evhtp_uri_t        * uri;
    evhtp_path_t       * path;
    evhtp_hooks_t      * hooks;
    evhtp_callback_t   * callback;
    evhtp_callback_cb    cb;
    void               * cbarg;

    if (request == NULL)
    {
        return -1;
    }

    if (evhtp_unlikely((evhtp = request->htp) == NULL))
    {
        return -1;
    }

    if (evhtp_unlikely((conn = request->conn) == NULL))
    {
        return -1;
    }

    if ((uri = request->uri) == NULL)
    {
        return -1;
    }

    if ((path = uri->path) == NULL)
    {
        return -1;
    }

    hooks    = NULL;
    callback = NULL;
    cb       = NULL;
    cbarg    = NULL;

    if ((callback = htp__callback_find_(evhtp->callbacks, path->full,
                                        &path->matched_soff, &path->matched_eoff)))
    {
        /* matched a callback using both path and file (/a/b/c/d) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else if ((callback = htp__callback_find_(evhtp->callbacks, path->path,
                                               &path->matched_soff, &path->matched_eoff)))
    {
        /* matched a callback using *just* the path (/a/b/c/) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else {
        /* no callbacks found for either case, use defaults */
        cb    = evhtp->defaults.cb_fini;
        cbarg = evhtp->defaults.cb_fini_arg;

        path->matched_soff = 0;
        path->matched_eoff = (unsigned int)strlen(path->full);
    }

    if (path->match_start == NULL)
    {
        path->match_start = calloc(strlen(path->full) + 1, 1);
        evhtp_alloc_assert(path->match_start);
    }

    if (path->match_end == NULL)
    {
        path->match_end = calloc(strlen(path->full) + 1, 1);
        evhtp_alloc_assert(path->match_end);
    }

    if (path->matched_soff != UINT_MAX /*ONIG_REGION_NOTPOS*/)
    {
        if (path->matched_eoff - path->matched_soff)
        {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   path->matched_eoff - path->matched_soff);
        } else {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   strlen((const char *)(path->full + path->matched_soff)));
        }

        memcpy(path->match_end,
               (void *)(path->full + path->matched_eoff),
               strlen(path->full) - path->matched_eoff);
    }

    if (hooks != NULL)
    {
        if (request->hooks == NULL)
        {
            request->hooks = malloc(sizeof(evhtp_hooks_t));
            evhtp_alloc_assert(request->hooks);
        }

        memcpy(request->hooks, hooks, sizeof(evhtp_hooks_t));
    }

    request->cb    = cb;
    request->cbarg = cbarg;

    return 0;
} /* htp__request_set_callbacks_ */

static int
htp__require_uri_(evhtp_connection_t * c)
{
    if (c && c->request && !c->request->uri)
    {
        c->request->uri = htp__uri_new_();
        evhtp_alloc_assert(c->request->uri);
    }

    return 0;
}

static int
htp__create_headers_(evhtp_header_t * header, void * arg)
{
    evbuf_t * buf = arg;

    evbuffer_expand(buf, header->klen + 2 + header->vlen + 2);
    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);

    return 0;
}

static evbuf_t *
htp__create_reply_(evhtp_request_t * request, evhtp_res code)
{
    evbuf_t     * buf;
    const char  * content_type;
    char          res_buf[2048];
    int           sres;
    size_t        out_len;
    unsigned char major;
    unsigned char minor;
    char          out_buf[64];


    content_type = evhtp_kv_find(request->headers_out, "Content-Type");
    out_len      = evbuffer_get_length(request->buffer_out);

    buf          = request->conn->scratch_buf;
    evhtp_assert(buf != NULL);

    evbuffer_drain(buf, -1);

    /*
     * buf          = evbuffer_new();
     * evhtp_alloc_assert(buf);
     */

    if (htparser_get_multipart(request->conn->parser) == 1)
    {
        goto check_proto;
    }

    if (out_len && request->chunked == 0)
    {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_kv_find(request->headers_out, "Content-Length"))
        {
            /* convert the buffer_out length to a string and set
             * and add the new Content-Length header.
             */
            evhtp_modp_sizetoa(out_len, out_buf);

            evhtp_kvs_add_kv(request->headers_out,
                             evhtp_kv_new("Content-Length", out_buf, 0, 1));
        }
    }
check_proto:
    /* add the proper keep-alive type headers based on http version */
    switch (request->proto) {
        case EVHTP_PROTO_11:
            if (request->keepalive == 0)
            {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_kvs_add_kv(request->headers_out,
                                 evhtp_kv_new("Connection", "close", 0, 0));
            }

            if (!evhtp_kv_find(request->headers_out, "Content-Length"))
            {
                evhtp_kvs_add_kv(request->headers_out,
                                 evhtp_kv_new("Content-Length", "0", 0, 0));
            }

            break;
        case EVHTP_PROTO_10:
            if (request->keepalive == 1)
            {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_kvs_add_kv(request->headers_out,
                                 evhtp_kv_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            /* this sometimes happens when a response is made but paused before
             * the method has been parsed */
            htparser_set_major(request->conn->parser, 1);
            htparser_set_minor(request->conn->parser, 0);
            break;
    } /* switch */


    if (!content_type)
    {
        evhtp_kvs_add_kv(request->headers_out,
                         evhtp_kv_new("Content-Type", "text/plain", 0, 0));
    }

    /* attempt to add the status line into a temporary buffer and then use
     * evbuffer_add(). Using plain old snprintf() will be faster than
     * evbuffer_add_printf(). If the snprintf() fails, which it rarely should,
     * we fallback to using evbuffer_add_printf().
     */

    major = evhtp_modp_uchartoa(htparser_get_major(request->conn->parser));
    minor = evhtp_modp_uchartoa(htparser_get_minor(request->conn->parser));

    evhtp_modp_u32toa((uint32_t)code, out_buf);

    sres  = snprintf(res_buf, sizeof(res_buf), "HTTP/%c.%c %s %s\r\n",
                     major, minor, out_buf, status_code_to_str(code));

    if (sres >= sizeof(res_buf) || sres < 0)
    {
        /* failed to fit the whole thing in the res_buf, so just fallback to
         * using evbuffer_add_printf().
         */
        evbuffer_add_printf(buf, "HTTP/%c.%c %d %s\r\n",
                            major, minor,
                            code, status_code_to_str(code));
    } else {
        /* copy the res_buf using evbuffer_add() instead of add_printf() */
        evbuffer_add(buf, res_buf, sres);
    }


    evhtp_kvs_for_each(request->headers_out, htp__create_headers_, buf);
    evbuffer_add(buf, "\r\n", 2);

    if (evbuffer_get_length(request->buffer_out))
    {
        evbuffer_add_buffer(buf, request->buffer_out);
    }

    return buf;
}     /* htp__create_reply_ */


static int
htp__run_pre_accept_(struct evhtp_ * htp, evhtp_connection_t * conn)
{
    void    * args;
    evhtp_res res;

    if (evhtp_likely(htp->defaults.cb_pre_accept == NULL))
    {
        return 0;
    }

    args = htp->defaults.cb_pre_accept_arg;
    res  = htp->defaults.cb_pre_accept(conn, args);

    if (res != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__connection_accept_(evbase_t * evbase, evhtp_connection_t * connection)
{
    struct timeval * c_recv_timeo;
    struct timeval * c_send_timeo;

    if (htp__run_pre_accept_(connection->htp, connection) < 0)
    {
        evutil_closesocket(connection->sock);

        return -1;
    }

#ifndef EVHTP_DISABLE_SSL
    if (connection->htp->ssl_ctx != NULL)
    {
        connection->ssl = SSL_new(connection->htp->ssl_ctx);
        connection->bev = bufferevent_openssl_socket_new(evbase,
                                                         connection->sock,
                                                         connection->ssl,
                                                         BUFFEREVENT_SSL_ACCEPTING,
                                                         connection->htp->htp_bev_flags);
        SSL_set_app_data(connection->ssl, connection);
        goto end;
    }
#endif

    connection->bev = bufferevent_socket_new(evbase,
                                             connection->sock,
                                             connection->htp->htp_bev_flags);

    htp_log_debug("enter sock=%d\n", connection->sock);

#ifndef EVHTP_DISABLE_SSL
end:
#endif

    if (connection->recv_timeo.tv_sec || connection->recv_timeo.tv_usec)
    {
        c_recv_timeo = &connection->recv_timeo;
    } else if (connection->htp->recv_timeo.tv_sec ||
               connection->htp->recv_timeo.tv_usec)
    {
        c_recv_timeo = &connection->htp->recv_timeo;
    } else {
        c_recv_timeo = NULL;
    }

    if (connection->send_timeo.tv_sec || connection->send_timeo.tv_usec)
    {
        c_send_timeo = &connection->send_timeo;
    } else if (connection->htp->send_timeo.tv_sec ||
               connection->htp->send_timeo.tv_usec)
    {
        c_send_timeo = &connection->htp->send_timeo;
    } else {
        c_send_timeo = NULL;
    }

    evhtp_connection_set_timeouts(connection, c_recv_timeo, c_send_timeo);

    connection->resume_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
                                      htp__connection_resumecb_, connection);
    event_add(connection->resume_ev, NULL);

    bufferevent_enable(connection->bev, EV_READ);
    bufferevent_setcb(connection->bev,
                      htp__connection_readcb_,
                      htp__connection_writecb_,
                      htp__connection_eventcb_, connection);

    return 0;
}     /* htp__connection_accept_ */

static void
htp__default_request_cb_(evhtp_request_t * request, void * arg)
{
    evhtp_kvs_add_kv(request->headers_out,
                     evhtp_kv_new("Content-Length", "0", 0, 0));
    evhtp_send_reply(request, EVHTP_RES_NOTFOUND);
}


#ifdef LIBEVENT_HAS_SHUTDOWN
#ifndef EVHTP_DISABLE_SSL
static void
htp__shutdown_eventcb_(evbev_t * bev, short events, void * arg)
{
}

#endif
#endif

static int
htp__run_post_accept_(struct evhtp_ * htp, evhtp_connection_t * connection)
{
    void    * args;
    evhtp_res res;

    if (evhtp_likely(htp->defaults.cb_post_accept == NULL))
    {
        return 0;
    }

    args = htp->defaults.cb_post_accept_arg;
    res  = htp->defaults.cb_post_accept(connection, args);

    if (res != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

#ifndef EVHTP_DISABLE_EVTHR
static void
htp__run_in_thread_(evthr_t * thr, void * arg, void * shared)
{
    struct evhtp_      * htp        = shared;
    evhtp_connection_t * connection = arg;

    connection->evbase = evthr_get_base(thr);
    connection->thread = thr;

    if (htp__connection_accept_(connection->evbase, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }

    if (htp__run_post_accept_(htp, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }
}

#endif

static void
htp__accept_cb_(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg)
{
    struct evhtp_      * htp = arg;
    evhtp_connection_t * connection;

    if (evhtp_unlikely(!(connection = htp__connection_new_(htp, fd, evhtp_type_server))))
    {
        return;
    }

    htp_log_debug("fd = %d, conn = %p", fd, connection);

    connection->saddr = malloc(sl);
    evhtp_alloc_assert(connection->saddr);

    memcpy(connection->saddr, s, sl);

#ifndef EVHTP_DISABLE_EVTHR
    if (htp->thr_pool != NULL)
    {
        if (evthr_pool_defer(htp->thr_pool,
                             htp__run_in_thread_, connection) != EVTHR_RES_OK)
        {
            evutil_closesocket(connection->sock);
            evhtp_connection_free(connection);

            return;
        }

        return;
    }
#endif
    connection->evbase = htp->evbase;

    if (htp__connection_accept_(htp->evbase, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }

    if (htp__run_post_accept_(htp, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }
} /* htp__accept_cb_ */

#ifndef EVHTP_DISABLE_SSL
#ifndef EVHTP_DISABLE_EVTHR
static unsigned long
htp__ssl_get_thread_id_(void)
{
#ifndef WIN32

    return (unsigned long)pthread_self();
#else

    return (unsigned long)(pthread_self().p);
#endif
}

static void
htp__ssl_thread_lock_(int mode, int type, const char * file, int line)
{
    if (type < ssl_num_locks)
    {
        if (mode & CRYPTO_LOCK)
        {
            pthread_mutex_lock(&(ssl_locks[type]));
        } else {
            pthread_mutex_unlock(&(ssl_locks[type]));
        }
    }
}

#endif
static void
htp__ssl_delete_scache_ent_(evhtp_ssl_ctx_t * ctx, evhtp_ssl_sess_t * sess)
{
    struct evhtp_   * htp;
    evhtp_ssl_cfg_t * cfg;
    unsigned char   * sid;
    unsigned int      slen;

    htp  = (struct evhtp_ *)SSL_CTX_get_app_data(ctx);
    cfg  = htp->ssl_cfg;

    sid  = sess->session_id;
    slen = sess->session_id_length;

    if (cfg->scache_del)
    {
        (cfg->scache_del)(htp, sid, slen);
    }
}

static int
htp__ssl_add_scache_ent_(evhtp_ssl_t * ssl, evhtp_ssl_sess_t * sess)
{
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    unsigned char      * sid;
    int                  slen;

    connection = (evhtp_connection_t *)SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;

    sid        = sess->session_id;
    slen       = sess->session_id_length;

    SSL_set_timeout(sess, cfg->scache_timeout);

    if (cfg->scache_add)
    {
        return (cfg->scache_add)(connection, sid, slen, sess);
    }

    return 0;
}

static evhtp_ssl_sess_t *
htp__ssl_get_scache_ent_(evhtp_ssl_t * ssl, unsigned char * sid, int sid_len, int * copy)
{
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    evhtp_ssl_sess_t   * sess;

    connection = (evhtp_connection_t * )SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;
    sess       = NULL;

    if (cfg->scache_get)
    {
        sess = (cfg->scache_get)(connection, sid, sid_len);
    }

    *copy = 0;

    return sess;
}

static int
htp__ssl_servername_(evhtp_ssl_t * ssl, int * unused, void * arg)
{
    const char         * sname;
    evhtp_connection_t * connection;
    struct evhtp_      * evhtp;
    struct evhtp_      * evhtp_vhost;

    if (!(sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(connection = SSL_get_app_data(ssl)))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(evhtp = connection->htp))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if ((evhtp_vhost = htp__request_find_vhost_(evhtp, sname)))
    {
        connection->htp           = evhtp_vhost;
        connection->vhost_via_sni = 1;

        SSL_set_SSL_CTX(ssl, evhtp_vhost->ssl_ctx);
        SSL_set_options(ssl, SSL_CTX_get_options(ssl->ctx));

        if ((SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE) ||
            (SSL_num_renegotiations(ssl) == 0))
        {
            SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ssl->ctx),
                           SSL_CTX_get_verify_callback(ssl->ctx));
        }

        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
} /* htp__ssl_servername_ */

#endif

/*
 * PUBLIC FUNCTIONS
 */


evhtp_header_t *
evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char kalloc)
{
    evhtp_header_t * header;

    if (!(header = evhtp_kv_new(key, NULL, kalloc, 0)))
    {
        return NULL;
    }

    evhtp_kvs_add_kv(headers, header);

    return header;
}

evhtp_header_t *
evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char valloc)
{
    evhtp_header_t * header;

    if (!headers || !val)
    {
        return NULL;
    }

    if (!(header = TAILQ_LAST(headers, evhtp_headers_s)))
    {
        return NULL;
    }

    if (header->val != NULL)
    {
        return NULL;
    }

    header->vlen = strlen(val);

    if (valloc == 1)
    {
        header->val = malloc(header->vlen + 1);
        header->val[header->vlen] = '\0';
        memcpy(header->val, val, header->vlen);
    } else {
        header->val = (char *)val;
    }

    header->v_heaped = valloc;

    return header;
}

typedef enum {
    s_query_start = 0,
    s_query_separator,
    s_query_key,
    s_query_val,
    s_query_key_hex_1,
    s_query_key_hex_2,
    s_query_val_hex_1,
    s_query_val_hex_2,
    s_query_done
} query_parser_state;

static inline int
evhtp_is_hex_query_char(unsigned char ch)
{
    switch (ch) {
        case 'a': case 'A':
        case 'b': case 'B':
        case 'c': case 'C':
        case 'd': case 'D':
        case 'e': case 'E':
        case 'f': case 'F':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':

            return 1;
        default:

            return 0;
    } /* switch */
}

enum unscape_state {
    unscape_state_start = 0,
    unscape_state_hex1,
    unscape_state_hex2
};

int
evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len)
{
    unsigned char    * optr;
    unsigned char    * sptr;
    unsigned char      d;
    unsigned char      ch;
    unsigned char      c;
    size_t             i;
    enum unscape_state state;

    if (out == NULL || *out == NULL)
    {
        return -1;
    }

    state = unscape_state_start;
    optr  = *out;
    sptr  = str;
    d     = 0;

    for (i = 0; i < str_len; i++)
    {
        ch = *sptr++;

        switch (state) {
            case unscape_state_start:
                if (ch == '%')
                {
                    state = unscape_state_hex1;
                    break;
                }

                *optr++ = ch;

                break;
            case unscape_state_hex1:
                if (ch >= '0' && ch <= '9')
                {
                    d     = (unsigned char)(ch - '0');
                    state = unscape_state_hex2;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f')
                {
                    d     = (unsigned char)(c - 'a' + 10);
                    state = unscape_state_hex2;
                    break;
                }

                state   = unscape_state_start;
                *optr++ = ch;
                break;
            case unscape_state_hex2:
                state   = unscape_state_start;

                if (ch >= '0' && ch <= '9')
                {
                    ch      = (unsigned char)((d << 4) + ch - '0');

                    *optr++ = ch;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f')
                {
                    ch      = (unsigned char)((d << 4) + c - 'a' + 10);
                    *optr++ = ch;
                    break;
                }

                break;
        } /* switch */
    }

    return 0;
}         /* evhtp_unescape_string */

evhtp_kvs_t *
evhtp_parse_query_wflags(const char * query, size_t len, int flags)
{
    evhtp_kvs_t    * query_args;
    query_parser_state state;
    size_t             key_idx;
    size_t             val_idx;
    unsigned char      ch;
    size_t             i;

    if (len > (SIZE_MAX - (len + 2)))
    {
        return NULL;
    }

    query_args = evhtp_kvs_new();

    state      = s_query_start;
    key_idx    = 0;
    val_idx    = 0;

#ifdef EVHTP_HAS_C99
    char key_buf[len + 1];
    char val_buf[len + 1];
#else
    char * key_buf;
    char * val_buf;

    key_buf = malloc(len + 1);
    evhtp_alloc_assert(key_buf);

    val_buf = malloc(len + 1);
    evhtp_alloc_assert(val_buf);
#endif

    for (i = 0; i < len; i++)
    {
        ch = query[i];

        if (key_idx >= len || val_idx >= len)
        {
            goto error;
        }

        switch (state) {
            case s_query_start:
                key_idx    = 0;
                val_idx    = 0;

                key_buf[0] = '\0';
                val_buf[0] = '\0';

                state      = s_query_key;
            /* Fall through. */
            case s_query_key:
                switch (ch) {
                    case '=':
                        state = s_query_val;
                        break;
                    case '%':
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';

                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX))
                        {
                            state = s_query_key_hex_1;
                        }

                        break;
                    case ';':
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP))
                        {
                            key_buf[key_idx++] = ch;
                            key_buf[key_idx]   = '\0';
                            break;
                        }

                    /* otherwise we fallthrough */
                    case '&':
                        /* in this state, we have a NULL value */
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS))
                        {
                            goto error;
                        }

                        /* insert the key with value of NULL and set the
                         * state back to parsing s_query_key.
                         */
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, NULL, 1, 1));

                        key_idx            = 0;
                        val_idx            = 0;

                        key_buf[0]         = '\0';
                        val_buf[0]         = '\0';

                        state              = s_query_key;
                        break;
                    default:
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';
                        break;
                } /* switch */
                break;
            case s_query_key_hex_1:
                if (!evhtp_is_hex_query_char(ch))
                {
                    /* not hex, so we treat as a normal key */
                    if ((key_idx + 2) >= len)
                    {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }

                    key_buf[key_idx - 1] = '%';
                    key_buf[key_idx++]   = ch;
                    key_buf[key_idx]     = '\0';

                    state = s_query_key;
                    break;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key_hex_2;
                break;
            case s_query_key_hex_2:
                if (!evhtp_is_hex_query_char(ch))
                {
                    goto error;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key;
                break;
            case s_query_val:
                switch (ch) {
                    case ';':
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP))
                        {
                            val_buf[val_idx++] = ch;
                            val_buf[val_idx]   = '\0';
                            break;
                        }
                    case '&':
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));

                        key_idx            = 0;
                        val_idx            = 0;

                        key_buf[0]         = '\0';
                        val_buf[0]         = '\0';
                        state              = s_query_key;

                        break;
                    case '%':
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX))
                        {
                            state = s_query_val_hex_1;
                        }

                        break;
                    default:
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        break;
                }     /* switch */
                break;
            case s_query_val_hex_1:
                if (!evhtp_is_hex_query_char(ch))
                {
                    /* not really a hex val */
                    if ((val_idx + 2) >= len)
                    {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }

                    if (val_idx == 0)
                    {
                        goto error;
                    }

                    val_buf[val_idx - 1] = '%';
                    val_buf[val_idx++]   = ch;
                    val_buf[val_idx]     = '\0';

                    state = s_query_val;
                    break;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val_hex_2;
                break;
            case s_query_val_hex_2:
                if (!evhtp_is_hex_query_char(ch))
                {
                    goto error;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val;
                break;
            default:
                /* bad state */
                goto error;
        }       /* switch */
    }

    if (key_idx)
    {
        do {
            if (val_idx)
            {
                evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));
                break;
            }

            if (state >= s_query_val)
            {
                if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_EMPTY_VALS))
                {
                    goto error;
                }

                evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, "", 1, 1));
                break;
            }

            if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS))
            {
                goto error;
            }

            evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, NULL, 1, 0));
        } while (0);
    }

#ifndef EVHTP_HAS_C99
    evhtp_safe_free(key_buf, free);
    evhtp_safe_free(val_buf, free);
#endif

    return query_args;
error:
#ifndef EVHTP_HAS_C99
    evhtp_safe_free(key_buf, free);
    evhtp_safe_free(val_buf, free);
#endif

    evhtp_kvs_free(query_args);

    return NULL;
}     /* evhtp_parse_query */

evhtp_kvs_t *
evhtp_parse_query(const char * query, size_t len)
{
    return evhtp_parse_query_wflags(query, len,
                                    EVHTP_PARSE_QUERY_FLAG_STRICT);
}

void
evhtp_send_reply_start(evhtp_request_t * request, evhtp_res code)
{
    evhtp_connection_t * c;
    evbuf_t            * reply_buf;

    c = evhtp_request_get_connection(request);

    if (!(reply_buf = htp__create_reply_(request, code)))
    {
        evhtp_connection_free(c);

        return;
    }

    bufferevent_write_buffer(c->bev, reply_buf);
    evbuffer_drain(reply_buf, -1);
    /* evbuffer_free(reply_buf); */
}

void
evhtp_send_reply_body(evhtp_request_t * request, evbuf_t * buf)
{
    evhtp_connection_t * c;

    c = request->conn;

    bufferevent_write_buffer(c->bev, buf);
}

void
evhtp_send_reply_end(evhtp_request_t * request)
{
    request->finished = 1;
}

void
evhtp_send_reply(evhtp_request_t * request, evhtp_res code)
{
    evhtp_connection_t * c;
    evbuf_t            * reply_buf;
    struct bufferevent * bev;

    c = evhtp_request_get_connection(request);
    request->finished = 1;

    if (!(reply_buf = htp__create_reply_(request, code)))
    {
        evhtp_connection_free(request->conn);

        return;
    }

    bev = evhtp_connection_get_bev(c);

    bufferevent_lock(bev);
    {
        bufferevent_write_buffer(bev, reply_buf);
    }
    bufferevent_unlock(bev);

    evbuffer_drain(reply_buf, -1);
    /* evbuffer_free(reply_buf); */
}

int
evhtp_response_needs_body(const evhtp_res code, const htp_method method)
{
    return code != EVHTP_RES_NOCONTENT &&
           code != EVHTP_RES_NOTMOD &&
           (code < 100 || code >= 200) &&
           method != htp_method_HEAD;
}

void
evhtp_send_reply_chunk_start(evhtp_request_t * request, evhtp_res code)
{
    evhtp_header_t * content_len;

    if (evhtp_response_needs_body(code, request->method))
    {
        content_len = evhtp_kvs_find_kv(request->headers_out, "Content-Length");

        switch (request->proto) {
            case EVHTP_PROTO_11:

                /*
                 * prefer HTTP/1.1 chunked encoding to closing the connection;
                 * note RFC 2616 section 4.4 forbids it with Content-Length:
                 * and it's not necessary then anyway.
                 */

                evhtp_kv_rm_and_free(request->headers_out, content_len);
                request->chunked = 1;
                break;
            case EVHTP_PROTO_10:
                /*
                 * HTTP/1.0 can be chunked as long as the Content-Length header
                 * is set to 0
                 */
                evhtp_kv_rm_and_free(request->headers_out, content_len);

#if 0
                evhtp_kvs_add_kv(request->headers_out,
                                 evhtp_kv_new("Content-Length", "0", 0, 0));
#endif

                request->chunked = 1;
                break;
            default:
                request->chunked = 0;
                break;
        } /* switch */
    } else {
        request->chunked = 0;
    }

    if (request->chunked == 1)
    {
        evhtp_kvs_add_kv(request->headers_out,
                         evhtp_kv_new("Transfer-Encoding", "chunked", 0, 0));

        /*
         * if data already exists on the output buffer, we automagically convert
         * it to the first chunk.
         */
        if (evbuffer_get_length(request->buffer_out) > 0)
        {
            char lstr[128];
            int  sres;

            sres = snprintf(lstr, sizeof(lstr), "%x\r\n",
                            (unsigned)evbuffer_get_length(request->buffer_out));

            if (sres >= sizeof(lstr) || sres < 0)
            {
                /* overflow condition, shouldn't ever get here, but lets
                 * terminate the connection asap */
                goto end;
            }

            evbuffer_prepend(request->buffer_out, lstr, strlen(lstr));
            evbuffer_add(request->buffer_out, "\r\n", 2);
        }
    }

end:
    evhtp_send_reply_start(request, code);
} /* evhtp_send_reply_chunk_start */

void
evhtp_send_reply_chunk(evhtp_request_t * request, evbuf_t * buf)
{
    evbuf_t * output;

    if (evbuffer_get_length(buf) == 0)
    {
        return;
    }

    output = bufferevent_get_output(request->conn->bev);

    if (request->chunked == 1)
    {
        evbuffer_add_printf(output, "%x\r\n",
                            (unsigned)evbuffer_get_length(buf));
    }

    evhtp_send_reply_body(request, buf);

    if (request->chunked)
    {
        evbuffer_add(output, "\r\n", 2);
    }

    bufferevent_flush(request->conn->bev, EV_WRITE, BEV_FLUSH);
}

void
evhtp_send_reply_chunk_end(evhtp_request_t * request)
{
    if (request->chunked == 1)
    {
        evbuffer_add(bufferevent_get_output(evhtp_request_get_bev(request)),
                     "0\r\n\r\n", 5);
    }

    evhtp_send_reply_end(request);
}

void
evhtp_unbind_socket(struct evhtp_ * htp)
{
    evhtp_safe_free(htp->server, evconnlistener_free);
}

int
evhtp_accept_socket(struct evhtp_ * htp, evutil_socket_t sock, int backlog)
{
    int on  = 1;
    int res = 0;

    evhtp_assert(htp != NULL);

    if (sock == -1)
    {
        return -1;
    }

    do {
#if defined SO_REUSEPORT
        if (htp->enable_reuseport)
        {
            if ((res = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on)) != 0))
            {
                break;
            }
        }
#endif

#if defined TCP_NODELAY
        if (htp->enable_nodelay == 1)
        {
            if ((res = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on))) != 0)
            {
                break;
            }
        }
#endif

#if defined TCP_DEFER_ACCEPT
        if (htp->enable_defer_accept == 1)
        {
            if ((res = setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (void *)&on, sizeof(on))) != 0)
            {
                break;
            }
        }
#endif

        htp->server = evconnlistener_new(htp->evbase, htp__accept_cb_, htp,
                                         LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                         backlog, sock);

        if (htp->server == NULL)
        {
            return -1;
        }

#ifndef EVHTP_DISABLE_SSL
        if (htp->ssl_ctx != NULL)
        {
            /* if ssl is enabled and we have virtual hosts, set our servername
             * callback. We do this here because we want to make sure that this gets
             * set after all potential virtualhosts have been set, not just after
             * ssl_init.
             */
            if (TAILQ_FIRST(&htp->vhosts) != NULL)
            {
                SSL_CTX_set_tlsext_servername_callback(htp->ssl_ctx,
                                                       htp__ssl_servername_);
            }
        }
#endif
    } while (0);
    return res;
} /* evhtp_accept_socket */

int
evhtp_bind_sockaddr(struct evhtp_ * htp, struct sockaddr * sa, size_t sin_len, int backlog)
{
#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    evutil_socket_t fd;
    int             on = 1;

    fd = socket(sa->sa_family, SOCK_STREAM, 0);
    evhtp_errno_assert(fd != -1);

    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);

    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));

    if (sa->sa_family == AF_INET6)
    {
        int rc;

        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        evhtp_errno_assert(rc != -1);
    }

    if (bind(fd, sa, sin_len) == -1)
    {
        return -1;
    }

    return evhtp_accept_socket(htp, fd, backlog);
} /* evhtp_bind_sockaddr */

int
evhtp_bind_socket(struct evhtp_ * htp, const char * baddr, uint16_t port, int backlog)
{
#ifndef NO_SYS_UN
    struct sockaddr_un sun;
#endif
    struct sockaddr_in6 sin6;
    struct sockaddr_in  sin;
    struct sockaddr   * sa;
    size_t              sin_len;

    memset(&sin, 0, sizeof(sin));

    if (!strncmp(baddr, "ipv6:", 5))
    {
        memset(&sin6, 0, sizeof(sin6));

        baddr           += 5;
        sin_len          = sizeof(struct sockaddr_in6);
        sin6.sin6_port   = htons(port);
        sin6.sin6_family = AF_INET6;

        evutil_inet_pton(AF_INET6, baddr, &sin6.sin6_addr);
        sa = (struct sockaddr *)&sin6;
    } else if (!strncmp(baddr, "unix:", 5))
    {
#ifndef NO_SYS_UN
        baddr += 5;

        if (strlen(baddr) >= sizeof(sun.sun_path))
        {
            return -1;
        }

        memset(&sun, 0, sizeof(sun));

        sin_len        = sizeof(struct sockaddr_un);
        sun.sun_family = AF_UNIX;

        strncpy(sun.sun_path, baddr, strlen(baddr));

        sa = (struct sockaddr *)&sun;
#else

        return -1;
#endif
    } else {
        if (!strncmp(baddr, "ipv4:", 5))
        {
            baddr += 5;
        }

        sin_len             = sizeof(struct sockaddr_in);

        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(port);
        sin.sin_addr.s_addr = inet_addr(baddr);

        sa = (struct sockaddr *)&sin;
    }

    return evhtp_bind_sockaddr(htp, sa, sin_len, backlog);
} /* evhtp_bind_socket */

void
evhtp_callbacks_free(evhtp_callbacks_t * callbacks)
{
    evhtp_callback_t * callback;
    evhtp_callback_t * tmp;

    if (callbacks == NULL)
    {
        return;
    }

    TAILQ_FOREACH_SAFE(callback, callbacks, next, tmp)
    {
        TAILQ_REMOVE(callbacks, callback, next);

        evhtp_safe_free(callback, evhtp_callback_free);
    }

    evhtp_safe_free(callbacks, free);
}

evhtp_callback_t *
evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    hcb        = calloc(sizeof(evhtp_callback_t), 1);
    evhtp_alloc_assert(hcb);

    hcb->type  = type;
    hcb->cb    = cb;
    hcb->cbarg = arg;

    switch (type) {
        case evhtp_callback_type_hash:
            hcb->hash      = htp__quick_hash_(path);
            hcb->val.path  = strdup(path);
            break;
#ifndef EVHTP_DISABLE_REGEX
        case evhtp_callback_type_regex:
            hcb->val.regex = malloc(sizeof(regex_t));

            if (regcomp(hcb->val.regex, (char *)path, REG_EXTENDED) != 0)
            {
                evhtp_safe_free(hcb->val.regex, free);
                evhtp_safe_free(hcb, free);

                return NULL;
            }
            break;
#endif
        case evhtp_callback_type_glob:
            hcb->val.glob = strdup(path);
            break;
        default:
            evhtp_safe_free(hcb, free);

            return NULL;
    } /* switch */

    return hcb;
}

void
evhtp_callback_free(evhtp_callback_t * callback)
{
    if (callback == NULL)
    {
        return;
    }

    switch (callback->type) {
        case evhtp_callback_type_hash:
            evhtp_safe_free(callback->val.path, free);
            break;
        case evhtp_callback_type_glob:
            evhtp_safe_free(callback->val.glob, free);
            break;
#ifndef EVHTP_DISABLE_REGEX
        case evhtp_callback_type_regex:
            regfree(callback->val.regex);
            evhtp_safe_free(callback->val.regex, free);
            break;
#endif
    }

    if (callback->hooks)
    {
        evhtp_safe_free(callback->hooks, free);
    }

    evhtp_safe_free(callback, free);

    return;
}

int
evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb)
{
    TAILQ_INSERT_TAIL(cbs, cb, next);

    return 0;
}

evhtp_callback_t *
evhtp_set_cb(struct evhtp_ * htp, const char * path, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(path, evhtp_callback_type_hash, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

evhtp_callback_t *
evhtp_get_cb(struct evhtp_ * htp, const char * path)
{
    evhtp_callback_t * callback;

    TAILQ_FOREACH(callback, htp->callbacks, next)
    {
        if (strcmp(callback->val.path, path) == 0)
        {
            return callback;
        }
    }

    return NULL;
}

#ifndef EVHTP_DISABLE_EVTHR
static void
htp__thread_init_(evthr_t * thr, void * arg)
{
    struct evhtp_ * htp = (struct evhtp_ *)arg;

    if (htp->thread_init_cb)
    {
        htp->thread_init_cb(htp, thr, htp->thread_cbarg);
    }
}

static void
htp__thread_exit_(evthr_t * thr, void * arg)
{
    struct evhtp_ * htp = (struct evhtp_ *)arg;

    if (htp->thread_exit_cb)
    {
        htp->thread_exit_cb(htp, thr, htp->thread_cbarg);
    }
}

static int
htp__use_threads_(struct evhtp_ * htp,
                  evhtp_thread_init_cb init_cb,
                  evhtp_thread_exit_cb exit_cb,
                  int nthreads, void * arg)
{
    if (htp == NULL)
    {
        return -1;
    }

    htp->thread_cbarg   = arg;
    htp->thread_init_cb = init_cb;
    htp->thread_exit_cb = exit_cb;

#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_use_threads();
#endif

    if (!(htp->thr_pool = evthr_pool_wexit_new(nthreads,
                                               htp__thread_init_,
                                               htp__thread_exit_, htp)))
    {
        return -1;
    }

    evthr_pool_start(htp->thr_pool);

    return 0;
}

int
evhtp_use_threads(struct evhtp_ * htp, evhtp_thread_init_cb init_cb,
                  int nthreads, void * arg)
{
    return htp___use_threads_(htp, init_cb, NULL, nthreads, arg);
}

int
evhtp_use_threads_wexit(struct evhtp_ * htp,
                        evhtp_thread_init_cb init_cb,
                        evhtp_thread_exit_cb exit_cb,
                        int nthreads, void * arg)
{
    return htp_use_threads_(htp, init_cb, exit_cb, nthreads, arg);
}

#endif

#ifndef EVHTP_DISABLE_EVTHR
int
evhtp_use_callback_locks(struct evhtp_ * htp)
{
    if (htp == NULL)
    {
        return -1;
    }

    if (!(htp->lock = malloc(sizeof(pthread_mutex_t))))
    {
        return -1;
    }

    return pthread_mutex_init(htp->lock, NULL);
}

#endif

#ifndef EVHTP_DISABLE_REGEX
evhtp_callback_t *
evhtp_set_regex_cb(struct evhtp_ * htp, const char * pattern, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_regex, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

#endif

evhtp_callback_t *
evhtp_set_glob_cb(struct evhtp_ * htp, const char * pattern, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_glob, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

void
evhtp_set_gencb(struct evhtp_ * htp, evhtp_callback_cb cb, void * arg)
{
    htp->defaults.cb_fini     = cb;
    htp->defaults.cb_fini_arg = arg;
}

void
evhtp_set_pre_accept_cb(struct evhtp_ * htp, evhtp_pre_accept_cb cb, void * arg)
{
    htp->defaults.cb_pre_accept     = cb;
    htp->defaults.cb_pre_accept_arg = arg;
}

void
evhtp_set_post_accept_cb(struct evhtp_ * htp, evhtp_post_accept_cb cb, void * arg)
{
    htp->defaults.cb_post_accept     = cb;
    htp->defaults.cb_post_accept_arg = arg;
}

#ifndef EVHTP_DISABLE_SSL
#ifndef EVHTP_DISABLE_EVTHR
int
evhtp_ssl_use_threads(void)
{
    int i;

    if (ssl_locks_initialized == 1)
    {
        return 0;
    }

    ssl_locks_initialized = 1;

    ssl_num_locks         = CRYPTO_num_locks();
    ssl_locks = malloc(ssl_num_locks * sizeof(evhtp_mutex_t));

    for (i = 0; i < ssl_num_locks; i++)
    {
        pthread_mutex_init(&(ssl_locks[i]), NULL);
    }

    CRYPTO_set_id_callback(htp__ssl_get_thread_id_);
    CRYPTO_set_locking_callback(htp__ssl_thread_lock_);

    return 0;
}

#endif

int
evhtp_ssl_init(struct evhtp_ * htp, evhtp_ssl_cfg_t * cfg)
{
#ifdef EVHTP_ENABLE_FUTURE_STUFF
    evhtp_ssl_scache_init init_cb = NULL;
    evhtp_ssl_scache_add  add_cb  = NULL;
    evhtp_ssl_scache_get  get_cb  = NULL;
    evhtp_ssl_scache_del  del_cb  = NULL;
#endif
    long cache_mode;

    if (cfg == NULL || htp == NULL || cfg->pemfile == NULL)
    {
        return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    RAND_poll();

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    STACK_OF(SSL_COMP) * comp_methods = SSL_COMP_get_compression_methods();
    sk_SSL_COMP_zero(comp_methods);
#endif

    htp->ssl_cfg = cfg;
    htp->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    evhtp_alloc_assert(htp->ssl_ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    SSL_CTX_set_options(htp->ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_timeout(htp->ssl_ctx, cfg->ssl_ctx_timeout);
#endif

    SSL_CTX_set_options(htp->ssl_ctx, cfg->ssl_opts);

#ifndef OPENSSL_NO_ECDH
    if (cfg->named_curve != NULL)
    {
        EC_KEY * ecdh = NULL;
        int      nid  = 0;

        nid  = OBJ_sn2nid(cfg->named_curve);
        if (nid == 0)
        {
            fprintf(stderr, "ECDH initialization failed: unknown curve %s\n", cfg->named_curve);
        }
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL)
        {
            fprintf(stderr, "ECDH initialization failed for curve %s\n", cfg->named_curve);
        }
        SSL_CTX_set_tmp_ecdh(htp->ssl_ctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif /* OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_DH
    if (cfg->dhparams != NULL)
    {
        FILE * fh;
        DH   * dh;

        fh = fopen(cfg->dhparams, "r");
        if (fh != NULL)
        {
            dh = PEM_read_DHparams(fh, NULL, NULL, NULL);
            if (dh != NULL)
            {
                SSL_CTX_set_tmp_dh(htp->ssl_ctx, dh);
                DH_free(dh);
            } else {
                fprintf(stderr, "DH initialization failed: unable to parse file %s\n", cfg->dhparams);
            }
            fclose(fh);
        } else {
            fprintf(stderr, "DH initialization failed: unable to open file %s\n", cfg->dhparams);
        }
    }
#endif /* OPENSSL_NO_DH */

    if (cfg->ciphers != NULL)
    {
        SSL_CTX_set_cipher_list(htp->ssl_ctx, cfg->ciphers);
    }

    SSL_CTX_load_verify_locations(htp->ssl_ctx, cfg->cafile, cfg->capath);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), cfg->store_flags);
    SSL_CTX_set_verify(htp->ssl_ctx, cfg->verify_peer, cfg->x509_verify_cb);

    if (cfg->x509_chk_issued_cb != NULL)
    {
        htp->ssl_ctx->cert_store->check_issued = cfg->x509_chk_issued_cb;
    }

    if (cfg->verify_depth)
    {
        SSL_CTX_set_verify_depth(htp->ssl_ctx, cfg->verify_depth);
    }

    switch (cfg->scache_type) {
        case evhtp_ssl_scache_type_disabled:
            cache_mode = SSL_SESS_CACHE_OFF;
            break;
#ifdef EVHTP_ENABLE_FUTURE_STUFF
        case evhtp_ssl_scache_type_user:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

            init_cb    = cfg->scache_init;
            add_cb     = cfg->scache_add;
            get_cb     = cfg->scache_get;
            del_cb     = cfg->scache_del;
            break;
        case evhtp_ssl_scache_type_builtin:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

            init_cb    = htp__ssl_builtin_init_;
            add_cb     = htp__ssl_builtin_add_;
            get_cb     = htp__ssl_builtin_get_;
            del_cb     = htp__ssl_builtin_del_;
            break;
#endif
        case evhtp_ssl_scache_type_internal:
        default:
            cache_mode = SSL_SESS_CACHE_SERVER;
            break;
    }     /* switch */

    SSL_CTX_use_certificate_file(htp->ssl_ctx, cfg->pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(htp->ssl_ctx,
                                cfg->privfile ? cfg->privfile : cfg->pemfile, SSL_FILETYPE_PEM);

    SSL_CTX_set_session_id_context(htp->ssl_ctx,
                                   (void *)&session_id_context,
                                   sizeof(session_id_context));

    SSL_CTX_set_app_data(htp->ssl_ctx, htp);
    SSL_CTX_set_session_cache_mode(htp->ssl_ctx, cache_mode);

    if (cache_mode != SSL_SESS_CACHE_OFF)
    {
        SSL_CTX_sess_set_cache_size(htp->ssl_ctx,
                                    cfg->scache_size ? cfg->scache_size : 1024);

        if (cfg->scache_type == evhtp_ssl_scache_type_builtin ||
            cfg->scache_type == evhtp_ssl_scache_type_user)
        {
            SSL_CTX_sess_set_new_cb(htp->ssl_ctx, htp__ssl_add_scache_ent_);
            SSL_CTX_sess_set_get_cb(htp->ssl_ctx, htp__ssl_get_scache_ent_);
            SSL_CTX_sess_set_remove_cb(htp->ssl_ctx, htp__ssl_delete_scache_ent_);

            if (cfg->scache_init)
            {
                cfg->args = (cfg->scache_init)(htp);
            }
        }
    }

    return 0;
}     /* evhtp_use_ssl */

#endif

evbev_t *
evhtp_connection_get_bev(evhtp_connection_t * connection)
{
    return connection->bev;
}

evbev_t *
evhtp_connection_take_ownership(evhtp_connection_t * connection)
{
    evbev_t * bev = evhtp_connection_get_bev(connection);

    if (connection->hooks)
    {
        evhtp_unset_all_hooks(&connection->hooks);
    }

    if (connection->request && connection->request->hooks)
    {
        evhtp_unset_all_hooks(&connection->request->hooks);
    }

    evhtp_connection_set_bev(connection, NULL);

    connection->owner = 0;

    bufferevent_disable(bev, EV_READ);
    bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

    return bev;
}

evbev_t *
evhtp_request_get_bev(evhtp_request_t * request)
{
    return evhtp_connection_get_bev(request->conn);
}

evbev_t *
evhtp_request_take_ownership(evhtp_request_t * request)
{
    return evhtp_connection_take_ownership(evhtp_request_get_connection(request));
}

void
evhtp_connection_set_bev(evhtp_connection_t * conn, evbev_t * bev)
{
    conn->bev = bev;
}

void
evhtp_request_set_bev(evhtp_request_t * request, evbev_t * bev)
{
    evhtp_connection_set_bev(request->conn, bev);
}

void
evhtp_request_set_keepalive(evhtp_request_t * request, int val)
{
    request->keepalive = (val > 0) ? 1 : 0;
}

evhtp_connection_t *
evhtp_request_get_connection(evhtp_request_t * request)
{
    return request->conn;
}

evhtp_proto
evhtp_request_get_proto(evhtp_request_t * request)
{
    return request->proto;
}

inline void
evhtp_connection_set_timeouts(evhtp_connection_t   * c,
                              const struct timeval * rtimeo,
                              const struct timeval * wtimeo)
{
    if (evhtp_unlikely(c == NULL))
    {
        return;
    }


    bufferevent_set_timeouts(c->bev, rtimeo, wtimeo);
}

void
evhtp_connection_set_max_body_size(evhtp_connection_t * c, uint64_t len)
{
    if (len == 0)
    {
        c->max_body_size = c->htp->max_body_size;
    } else {
        c->max_body_size = len;
    }
}

void
evhtp_request_set_max_body_size(evhtp_request_t * req, uint64_t len)
{
    evhtp_connection_set_max_body_size(req->conn, len);
}

void
evhtp_connection_free(evhtp_connection_t * connection)
{
    if (evhtp_unlikely(connection == NULL))
    {
        return;
    }

    htp__hook_connection_fini_(connection);

    evhtp_safe_free(connection->request, htp__request_free_);
    evhtp_safe_free(connection->parser, free);
    evhtp_safe_free(connection->hooks, free);
    evhtp_safe_free(connection->saddr, free);
    evhtp_safe_free(connection->scratch_buf, evbuffer_free);

    if (connection->resume_ev)
    {
        evhtp_safe_free(connection->resume_ev, event_free);
    }

    if (connection->bev)
    {
#ifdef LIBEVENT_HAS_SHUTDOWN
        bufferevent_shutdown(connection->bev, htp__shutdown_eventcb_);
#else
#ifndef EVHTP_DISABLE_SSL
        if (connection->ssl != NULL)
        {
            SSL_set_shutdown(connection->ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(connection->ssl);
        }
#endif
        bufferevent_free(connection->bev);
#endif
    }

    evhtp_safe_free(connection, free);
}     /* evhtp_connection_free */

void
evhtp_request_free(evhtp_request_t * request)
{
    htp__request_free_(request);
}

void
evhtp_set_timeouts(struct evhtp_ * htp, const struct timeval * r_timeo, const struct timeval * w_timeo)
{
    if (r_timeo != NULL)
    {
        htp->recv_timeo = *r_timeo;
    }

    if (w_timeo != NULL)
    {
        htp->send_timeo = *w_timeo;
    }
}

void
evhtp_set_max_keepalive_requests(struct evhtp_ * htp, uint64_t num)
{
    htp->max_keepalive_requests = num;
}

/**
 * @brief set bufferevent flags, defaults to BEV_OPT_CLOSE_ON_FREE
 *
 * @param htp
 * @param flags
 */
void
evhtp_set_bev_flags(struct evhtp_ * htp, int flags)
{
    htp->htp_bev_flags = flags;
}

void
evhtp_set_max_body_size(struct evhtp_ * htp, uint64_t len)
{
    htp->max_body_size = len;
}

void
evhtp_disable_100_continue(struct evhtp_ * htp)
{
    htp->disable_100_cont = 1;
}

void
evhtp_set_parser_flags(struct evhtp_ * htp, int flags)
{
    htp->parser_flags = flags;
}

int
evhtp_add_alias(struct evhtp_ * evhtp, const char * name)
{
    evhtp_alias_t * alias;

    if (evhtp_unlikely(evhtp == NULL || name == NULL))
    {
        return -1;
    }

    if (!(alias = calloc(sizeof(evhtp_alias_t), 1)))
    {
        return -1;
    }

    alias->alias = strdup(name);
    evhtp_alloc_assert(alias->alias);

    TAILQ_INSERT_TAIL(&evhtp->aliases, alias, next);

    return 0;
}

/**
 * @brief add a virtual host.
 *
 * NOTE: If SSL is being used and the vhost was found via SNI, the Host: header
 *       will *NOT* be used to find a matching vhost.
 *
 *       Also, any hooks which are set prior to finding a vhost that are hooks
 *       which are after the host hook, they are overwritten by the callbacks
 *       and hooks set for the vhost specific struct evhtp_ structure.
 *
 * @param evhtp
 * @param name
 * @param vhost
 *
 * @return
 */
int
evhtp_add_vhost(struct evhtp_ * evhtp, const char * name, struct evhtp_ * vhost)
{
    if (evhtp == NULL || name == NULL || vhost == NULL)
    {
        return -1;
    }

    if (TAILQ_FIRST(&vhost->vhosts) != NULL)
    {
        /* vhosts cannot have secondary vhosts defined */
        return -1;
    }

    if (!(vhost->server_name = strdup(name)))
    {
        return -1;
    }

    /* set the parent of this vhost so when the request has been completely
     * serviced, the vhost can be reset to the original evhtp structure.
     *
     * This allows for a keep-alive connection to make multiple requests with
     * different Host: values.
     */
    vhost->parent                 = evhtp;

    /* inherit various flags from the parent evhtp structure */
    vhost->htp_bev_flags          = evhtp->htp_bev_flags;
    vhost->max_body_size          = evhtp->max_body_size;
    vhost->max_keepalive_requests = evhtp->max_keepalive_requests;
    vhost->recv_timeo             = evhtp->recv_timeo;
    vhost->send_timeo             = evhtp->send_timeo;

    TAILQ_INSERT_TAIL(&evhtp->vhosts, vhost, next_vhost);

    return 0;
}

struct evhtp_ *
evhtp_new(evbase_t * evbase, void * arg)
{
    struct evhtp_ * htp;

    evhtp_assert(evbase != NULL);

    htp                = calloc(sizeof(evhtp_t), 1);
    evhtp_alloc_assert(htp);

    htp->arg           = arg;
    htp->evbase        = evbase;
    htp->htp_bev_flags = BEV_OPT_CLOSE_ON_FREE;

    /* default to lenient argument parsing */
    htp->parser_flags  = EVHTP_PARSE_QUERY_FLAG_LENIENT;


    TAILQ_INIT(&htp->vhosts);
    TAILQ_INIT(&htp->aliases);

    evhtp_set_gencb(htp, htp__default_request_cb_, (void *)htp);

    return htp;
}

void
evhtp_free(struct evhtp_ * evhtp)
{
    evhtp_alias_t * evhtp_alias, * tmp;

    if (evhtp == NULL)
    {
        return;
    }

#ifndef EVHTP_DISABLE_EVTHR
    if (evhtp->thr_pool)
    {
        evthr_pool_stop(evhtp->thr_pool);
        evthr_pool_free(evhtp->thr_pool);
    }
#endif

#ifndef EVHTP_DISABLE_SSL
    if (evhtp->ssl_ctx)
    {
        evhtp_safe_free(evhtp->ssl_ctx, SSL_CTX_free);
    }
#endif

    if (evhtp->server_name)
    {
        evhtp_safe_free(evhtp->server_name, free);
    }

    if (evhtp->callbacks)
    {
        evhtp_safe_free(evhtp->callbacks, evhtp_callbacks_free);
    }

    TAILQ_FOREACH_SAFE(evhtp_alias, &evhtp->aliases, next, tmp)
    {
        if (evhtp_alias->alias != NULL)
        {
            evhtp_safe_free(evhtp_alias->alias, free);
        }

        TAILQ_REMOVE(&evhtp->aliases, evhtp_alias, next);
        evhtp_safe_free(evhtp_alias, free);
    }

    evhtp_safe_free(evhtp, free);
} /* evhtp_free */

/*****************************************************************
* client request functions                                      *
*****************************************************************/

evhtp_connection_t *
evhtp_connection_new(evbase_t * evbase, const char * addr, uint16_t port)
{
    return evhtp_connection_new_dns(evbase, NULL, addr, port);
}

evhtp_connection_t *
evhtp_connection_new_dns(evbase_t * evbase, struct evdns_base * dns_base,
                         const char * addr, uint16_t port)
{
    evhtp_connection_t * conn;
    int                  err;

    evhtp_assert(evbase != NULL);

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client)))
    {
        return NULL;
    }

    conn->evbase = evbase;
    conn->bev    = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    if (conn->bev == NULL)
    {
        evhtp_connection_free(conn);

        return NULL;
    }

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, NULL, NULL,
                      htp__connection_eventcb_, conn);

    if (dns_base != NULL)
    {
        err = bufferevent_socket_connect_hostname(conn->bev, dns_base,
                                                  AF_UNSPEC, addr, port);
    } else {
        struct sockaddr_in  sin4;
        struct sockaddr_in6 sin6;
        struct sockaddr   * sin;
        int                 salen;

        if (inet_pton(AF_INET, addr, &sin4.sin_addr))
        {
            sin4.sin_family = AF_INET;
            sin4.sin_port   = htons(port);
            sin = (struct sockaddr *)&sin4;
            salen           = sizeof(sin4);
        } else if (inet_pton(AF_INET6, addr, &sin6.sin6_addr))
        {
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port   = htons(port);
            sin = (struct sockaddr *)&sin6;
            salen = sizeof(sin6);
        } else {
            /* Not a valid IP. */
            evhtp_connection_free(conn);

            return NULL;
        }

        err = bufferevent_socket_connect(conn->bev, sin, salen);
    }

    /* not needed since any of the bufferevent errors will go straight to
     * the eventcb
     */
    if (err)
    {
        return NULL;
    }

    return conn;
} /* evhtp_connection_new_dns */

#ifndef EVHTP_DISABLE_SSL
evhtp_connection_t *
evhtp_connection_ssl_new(evbase_t * evbase, const char * addr, uint16_t port, evhtp_ssl_ctx_t * ctx)
{
    evhtp_connection_t * conn;
    struct sockaddr_in   sin;
    int                  rc;

    evhtp_assert(evbase != NULL);

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client)))
    {
        return NULL;
    }

    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr(addr);
    sin.sin_port        = htons(port);

    conn->ssl           = SSL_new(ctx);
    evhtp_assert(conn->ssl != NULL);

    conn->evbase        = evbase;
    conn->bev           = bufferevent_openssl_socket_new(evbase, -1, conn->ssl,
                                                         BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    evhtp_assert(conn->bev != NULL);

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, NULL, NULL,
                      htp__connection_eventcb_, conn);

    rc = bufferevent_socket_connect(conn->bev,
                                    (struct sockaddr *)&sin, sizeof(sin));

    evhtp_assert(rc == 0);

    return conn;
}

#endif


evhtp_request_t *
evhtp_request_new(evhtp_callback_cb cb, void * arg)
{
    evhtp_request_t * r;

    r        = htp__request_new_(NULL);
    evhtp_alloc_assert(r);

    r->cb    = cb;
    r->cbarg = arg;
    r->proto = EVHTP_PROTO_11;

    return r;
}

int
evhtp_make_request(evhtp_connection_t * c, evhtp_request_t * r,
                   htp_method meth, const char * uri)
{
    evbuf_t * obuf;
    char    * proto;

    obuf       = bufferevent_get_output(c->bev);
    r->conn    = c;
    c->request = r;

    switch (r->proto) {
        case EVHTP_PROTO_10:
            proto = "1.0";
            break;
        case EVHTP_PROTO_11:
        default:
            proto = "1.1";
            break;
    }

    evbuffer_add_printf(obuf, "%s %s HTTP/%s\r\n",
                        htparser_get_methodstr_m(meth), uri, proto);

    evhtp_kvs_for_each(r->headers_out, htp__create_headers_, obuf);
    evbuffer_add_reference(obuf, "\r\n", 2, NULL, NULL);
    if (evbuffer_get_length(r->buffer_out))
    {
        evbuffer_add_buffer(obuf, r->buffer_out);
    }

    return 0;
}

unsigned int
evhtp_request_status(evhtp_request_t * r)
{
    return htparser_get_status(r->conn->parser);
}

