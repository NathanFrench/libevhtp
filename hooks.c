#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

struct evhtp_hooks_ {
    evhtp_hook_headers_start_cb   on_headers_start;
    evhtp_hook_header_cb          on_header;
    evhtp_hook_headers_cb         on_headers;
    evhtp_hook_path_cb            on_path;
    evhtp_hook_read_cb            on_read;
    evhtp_hook_request_fini_cb    on_request_fini;
    evhtp_hook_connection_fini_cb on_connection_fini;
    evhtp_hook_conn_err_cb        on_connection_error;
    evhtp_hook_err_cb             on_error;
    evhtp_hook_chunk_new_cb       on_new_chunk;
    evhtp_hook_chunk_fini_cb      on_chunk_fini;
    evhtp_hook_chunks_fini_cb     on_chunks_fini;
    evhtp_hook_hostname_cb        on_hostname;
    evhtp_hook_write_cb           on_write;
    evhtp_hook_event_cb           on_event;

    void * on_headers_start_arg;
    void * on_header_arg;
    void * on_headers_arg;
    void * on_path_arg;
    void * on_read_arg;
    void * on_request_fini_arg;
    void * on_connection_fini_arg;
    void * on_connection_error_arg;
    void * on_error_arg;
    void * on_new_chunk_arg;
    void * on_chunk_fini_arg;
    void * on_chunks_fini_arg;
    void * on_hostname_arg;
    void * on_write_arg;
    void * on_event_arg;
};


#define HOOK_AVAIL(var, hook_name)                   (var->hooks && var->hooks->hook_name)
#define HOOK_FUNC(var, hook_name)                    (var->hooks->hook_name)
#define HOOK_ARGS(var, hook_name)                    var->hooks->hook_name ## _arg

#define HOOK_REQUEST_RUN(request, hook_name, ...)    do {                                     \
        if (HOOK_AVAIL(request, hook_name))                                                   \
        {                                                                                     \
            return HOOK_FUNC(request, hook_name) (request, __VA_ARGS__,                       \
                                                  HOOK_ARGS(request, hook_name));             \
        }                                                                                     \
                                                                                              \
        if (request->conn && HOOK_AVAIL(request->conn, hook_name))                            \
        {                                                                                     \
            return HOOK_FUNC(request->conn, hook_name) (request, __VA_ARGS__,                 \
                                                        HOOK_ARGS(request->conn, hook_name)); \
        }                                                                                     \
} while (0)

#define HOOK_REQUEST_RUN_NARGS(__request, hook_name) do {                                         \
        if (HOOK_AVAIL(__request, hook_name))                                                     \
        {                                                                                         \
            return HOOK_FUNC(__request, hook_name) (__request,                                    \
                                                    HOOK_ARGS(__request, hook_name));             \
        }                                                                                         \
                                                                                                  \
        if (__request->conn && HOOK_AVAIL(__request->conn, hook_name))                            \
        {                                                                                         \
            return HOOK_FUNC(__request->conn, hook_name) (request,                                \
                                                          HOOK_ARGS(__request->conn, hook_name)); \
        }                                                                                         \
} while (0);

/**
 * @brief runs the user-defined on_path hook for a request
 *
 * @param request the request structure
 * @param path the path structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
htp__hook_path_(evhtp_request_t * request, evhtp_path_t * path)
{
    HOOK_REQUEST_RUN(request, on_path, path);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_header hook for a request
 *
 * once a full key: value header has been parsed, this will call the hook
 *
 * @param request the request strucutre
 * @param header the header structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
htp__hook_header_(evhtp_request_t * request, evhtp_header_t * header)
{
    HOOK_REQUEST_RUN(request, on_header, header);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_Headers hook for a request after all headers
 *        have been parsed.
 *
 * @param request the request structure
 * @param headers the headers tailq structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
htp__hook_headers_(evhtp_request_t * request, evhtp_headers_t * headers)
{
    HOOK_REQUEST_RUN(request, on_headers, headers);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_body hook for requests containing a body.
 *        the data is stored in the request->buffer_in so the user may either
 *        leave it, or drain upon being called.
 *
 * @param request the request strucutre
 * @param buf a evbuffer containing body data
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
htp__hook_body_(evhtp_request_t * request, evbuf_t * buf)
{
    if (request == NULL)
    {
        return 500;
    }

    HOOK_REQUEST_RUN(request, on_read, buf);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined hook called just prior to a request been
 *        free()'d
 *
 * @param request therequest structure
 *
 * @return EVHTP_RES_OK on success, otherwise treated as an error
 */
static evhtp_res
htp__hook_request_fini_(evhtp_request_t * request)
{
    if (request == NULL)
    {
        return 500;
    }

    HOOK_REQUEST_RUN_NARGS(request, on_request_fini);

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_chunk_new_(evhtp_request_t * request, uint64_t len)
{
    HOOK_REQUEST_RUN(request, on_new_chunk, len);

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_chunk_fini_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_chunk_fini);

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_chunks_fini_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_chunks_fini);

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_headers_start_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_headers_start);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-definedhook called just prior to a connection being
 *        closed
 *
 * @param connection the connection structure
 *
 * @return EVHTP_RES_OK on success, but pretty much ignored in any case.
 */
static evhtp_res
htp__hook_connection_fini_(evhtp_connection_t * connection)
{
    if (evhtp_unlikely(connection == NULL))
    {
        return 500;
    }

    if (connection->hooks != NULL && connection->hooks->on_connection_fini != NULL)
    {
        return (connection->hooks->on_connection_fini)(connection,
                                                       connection->hooks->on_connection_fini_arg);
    }

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined hook when a connection error occurs
 *
 * @param request the request structure
 * @param errtype the error that ocurred
 */
static void
htp__hook_error_(evhtp_request_t * request, evhtp_error_flags errtype)
{
    if (request && request->hooks && request->hooks->on_error)
    {
        (*request->hooks->on_error)(request, errtype,
                                    request->hooks->on_error_arg);
    }
}

/**
 * @brief runs the user-defined hook when a connection error occurs
 *
 * @param connection the connection structure
 * @param errtype the error that ocurred
 */
static evhtp_res
htp__hook_connection_error_(evhtp_connection_t * connection, evhtp_error_flags errtype)
{
    if (connection == NULL)
    {
        return EVHTP_RES_FATAL;
    }

    if (connection->request != NULL)
    {
        htp__hook_error_(connection->request, errtype);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_hostname_(evhtp_request_t * r, const char * hostname)
{
    HOOK_REQUEST_RUN(r, on_hostname, hostname);

    return EVHTP_RES_OK;
}

static evhtp_res
htp__hook_connection_write_(evhtp_connection_t * connection)
{
    if (connection->hooks && connection->hooks->on_write)
    {
        return (connection->hooks->on_write)(connection,
                                             connection->hooks->on_write_arg);
    }

    return EVHTP_RES_OK;
}

static int
htp__hook_set_(struct evhtp_hooks_ ** hooks, evhtp_hook_type type, evhtp_hook cb, void * arg)
{
    if (*hooks == NULL)
    {
        if (!(*hooks = calloc(sizeof(struct evhtp_hooks_), 1)))
        {
            return -1;
        }
    }

    switch (type) {
        case evhtp_hook_on_headers_start:
            (*hooks)->on_headers_start        = (evhtp_hook_headers_start_cb)cb;
            (*hooks)->on_headers_start_arg    = arg;
            break;
        case evhtp_hook_on_header:
            (*hooks)->on_header = (evhtp_hook_header_cb)cb;
            (*hooks)->on_header_arg           = arg;
            break;
        case evhtp_hook_on_headers:
            (*hooks)->on_headers              = (evhtp_hook_headers_cb)cb;
            (*hooks)->on_headers_arg          = arg;
            break;
        case evhtp_hook_on_path:
            (*hooks)->on_path = (evhtp_hook_path_cb)cb;
            (*hooks)->on_path_arg             = arg;
            break;
        case evhtp_hook_on_read:
            (*hooks)->on_read = (evhtp_hook_read_cb)cb;
            (*hooks)->on_read_arg             = arg;
            break;
        case evhtp_hook_on_request_fini:
            (*hooks)->on_request_fini         = (evhtp_hook_request_fini_cb)cb;
            (*hooks)->on_request_fini_arg     = arg;
            break;
        case evhtp_hook_on_connection_fini:
            (*hooks)->on_connection_fini      = (evhtp_hook_connection_fini_cb)cb;
            (*hooks)->on_connection_fini_arg  = arg;
            break;
        case evhtp_hook_on_conn_error:
            (*hooks)->on_connection_error     = (evhtp_hook_conn_err_cb)cb;
            (*hooks)->on_connection_error_arg = arg;
            break;
        case evhtp_hook_on_error:
            (*hooks)->on_error = (evhtp_hook_err_cb)cb;
            (*hooks)->on_error_arg            = arg;
            break;
        case evhtp_hook_on_new_chunk:
            (*hooks)->on_new_chunk            = (evhtp_hook_chunk_new_cb)cb;
            (*hooks)->on_new_chunk_arg        = arg;
            break;
        case evhtp_hook_on_chunk_complete:
            (*hooks)->on_chunk_fini           = (evhtp_hook_chunk_fini_cb)cb;
            (*hooks)->on_chunk_fini_arg       = arg;
            break;
        case evhtp_hook_on_chunks_complete:
            (*hooks)->on_chunks_fini          = (evhtp_hook_chunks_fini_cb)cb;
            (*hooks)->on_chunks_fini_arg      = arg;
            break;
        case evhtp_hook_on_hostname:
            (*hooks)->on_hostname             = (evhtp_hook_hostname_cb)cb;
            (*hooks)->on_hostname_arg         = arg;
            break;
        case evhtp_hook_on_write:
            (*hooks)->on_write = (evhtp_hook_write_cb)cb;
            (*hooks)->on_write_arg            = arg;
            break;
        case evhtp_hook_on_event:
            (*hooks)->on_event = (evhtp_hook_event_cb)cb;
            (*hooks)->on_event_arg            = arg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
}         /* htp__hook_set_ */

static int
htp__hook_unset_(struct evhtp_hooks_ ** hooks, evhtp_hook_type type)
{
    return htp__hook_set_(hooks, type, NULL, NULL);
}

static int
htp__hook_unset_all(struct evhtp_hooks_ ** hooks)
{
    int res = 0;

    if (htp__hook_unset_(hooks, evhtp_hook_on_headers_start))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_header))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_headers))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_path))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_read))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_request_fini))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_connection_fini))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_conn_error))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_error))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_new_chunk))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_chunk_complete))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_chunks_complete))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_hostname))
    {
        res -= 1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_write))
    {
        return -1;
    }

    if (htp__hook_unset_(hooks, evhtp_hook_on_event))
    {
        return -1;
    }

    return res;
} /* htp__hook_unset_all */

