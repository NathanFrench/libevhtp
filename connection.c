#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

struct evhtp_connection_ {
    evhtp_t            * htp;
    struct event_base  * evbase;
    struct bufferevent * bev;
#ifndef EVHTP_DISABLE_EVTHR
    evthr_t * thread;
#endif
#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_t * ssl;
#endif
    evhtp_hooks_t   * hooks;
    htparser        * parser;
    event_t         * resume_ev;
    struct sockaddr * saddr;
    struct timeval    recv_timeo;          /**< conn read timeouts (overrides global) */
    struct timeval    send_timeo;          /**< conn write timeouts (overrides global) */
    evutil_socket_t   sock;
    evhtp_request_t * request;             /**< the request currently being processed */
    uint64_t          max_body_size;
    uint64_t          body_bytes_read;
    uint64_t          num_requests;
    evhtp_type        type;                /**< server or client */
    uint8_t           error           : 1,
                      owner           : 1, /**< set to 1 if this structure owns the bufferevent */
                      vhost_via_sni   : 1, /**< set to 1 if the vhost was found via SSL SNI */
                      paused          : 1, /**< this connection has been marked as paused */
                      connected       : 1, /**< client specific - set after successful connection */
                      waiting         : 1, /**< used to make sure resuming  happens AFTER sending a reply */
                      free_connection : 1,
                      keepalive       : 1; /**< set to 1 after the first request has been processed and the connection is kept open */
    struct evbuffer * scratch_buf;         /**< always zero'd out after used */

#ifdef EVHTP_FUTURE_USE
    TAILQ_HEAD(, evhtp_request_s) pending; /**< client pending data */
#endif
};


static void
htp__connection_resumecb_(int fd, short events, void * arg)
{
    struct evhtp_connection_ * c = arg;

    c->paused = 0;

    if (c->request)
    {
        c->request->status = EVHTP_RES_OK;
    }

    if (c->free_connection == 1)
    {
        evhtp_connection_free(c);

        return;
    }

    /* XXX this is a hack to show a potential fix for issues/86, the main indea
     * is that you call resume AFTER you have sent the reply (not BEFORE).
     *
     * When it has been decided this is a proper fix, the pause bit should be
     * changed to a state-type flag.
     */

    if (evbuffer_get_length(bufferevent_get_output(c->bev)))
    {
        bufferevent_enable(c->bev, EV_WRITE);
        c->waiting = 1;
    } else {
        bufferevent_enable(c->bev, EV_READ | EV_WRITE);
        htp__connection_readcb_(c->bev, c);
    }
}

static void
htp__connection_readcb_(struct bufferevent * bev, void * arg)
{
    struct evhtp_connection_ * c = arg;
    void                     * buf;
    size_t                     nread;
    size_t                     avail;

    htp_log_debug("enter sock = %d", c->sock);

    avail = evbuffer_get_length(bufferevent_get_input(bev));

    htp_log_debug("available bytes %zu", avail);

    if (evhtp_unlikely(avail == 0))
    {
        return;
    }

    if (c->request)
    {
        c->request->status = EVHTP_RES_OK;
    }

    if (c->paused == 1)
    {
        return;
    }

    buf   = evbuffer_pullup(bufferevent_get_input(bev), avail);

    htp_log_debug("buffer is\n----\n%.*s\n-----", (int)avail, (const char *)buf);

    nread = htparser_run(c->parser, &request_psets, (const char *)buf, avail);

    htp_log_debug("nread = %zu", nread);

    if (evhtp_unlikely(c->owner != 1))
    {
        /*
         * someone has taken the ownership of this connection, we still need to
         * drain the input buffer that had been read up to this point.
         */
        evbuffer_drain(bufferevent_get_input(bev), nread);
        evhtp_connection_free(c);

        return;
    }

    if (c->request)
    {
        switch (c->request->status) {
            case EVHTP_RES_DATA_TOO_LONG:
                htp__hook_connection_error_(c, -1);
                evhtp_connection_free(c);

                return;
            default:
                break;
        }
    }

    evbuffer_drain(bufferevent_get_input(bev), nread);

    if (c->request && c->request->status == EVHTP_RES_PAUSE)
    {
        evhtp_request_pause(c->request);
    } else if (htparser_get_error(c->parser) != htparse_error_none)
    {
        evhtp_connection_free(c);
    } else if (nread < avail)
    {
        /* we still have more data to read (piped request probably) */
        evhtp_connection_resume(c);
    }
} /* htp__connection_readcb_ */

static void
htp__connection_writecb_(struct bufferevent * bev, void * arg)
{
    struct evhtp_connection_ * c = arg;

    htp_log_debug("c->request = %p", c->request);

    if (evhtp_unlikely(c->request == NULL))
    {
        return;
    }

    htp__hook_connection_write_(c);

    if (evhtp_unlikely(c->paused == 1))
    {
        return;
    }

    if (evhtp_unlikely(c->waiting == 1))
    {
        c->waiting = 0;

        bufferevent_enable(bev, EV_READ);

        if (evbuffer_get_length(bufferevent_get_input(bev)))
        {
            htp__connection_readcb_(bev, arg);
        }

        return;
    }

    if (c->request->finished == 0 || evbuffer_get_length(bufferevent_get_output(bev)))
    {
        return;
    }

    /*
     * if there is a set maximum number of keepalive requests configured, check
     * to make sure we are not over it. If we have gone over the max we set the
     * keepalive bit to 0, thus closing the connection.
     */
    if (c->htp->max_keepalive_requests)
    {
        if (++c->num_requests >= c->htp->max_keepalive_requests)
        {
            c->request->keepalive = 0;
        }
    }

    if (c->request->keepalive == 1)
    {
        htp__request_free_(c->request);

        c->keepalive       = 1;
        c->request         = NULL;
        c->body_bytes_read = 0;

        if (c->htp->parent && c->vhost_via_sni == 0)
        {
            /* this request was servied by a virtual host struct evhtp_ structure
             * which was *NOT* found via SSL SNI lookup. In this case we want to
             * reset our connections struct evhtp_ structure back to the original so
             * that subsequent requests can have a different Host: header.
             */
            struct evhtp_ * orig_htp = c->htp->parent;

            c->htp = orig_htp;
        }

        htparser_init(c->parser, htp_type_request);
        htparser_set_userdata(c->parser, c);

        return;
    } else {
        evhtp_connection_free(c);

        return;
    }

    return;
} /* htp__connection_writecb_ */

static void
htp__connection_eventcb_(struct bufferevent * bev, short events, void * arg)
{
    struct evhtp_connection_ * c = arg;

    if (c->hooks && c->hooks->on_event)
    {
        (c->hooks->on_event)(c, events, c->hooks->on_event_arg);
    }

    if ((events & BEV_EVENT_CONNECTED))
    {
        if (evhtp_likely(c->type == evhtp_type_client))
        {
            c->connected = 1;
            bufferevent_setcb(bev,
                              htp__connection_readcb_,
                              htp__connection_writecb_,
                              htp__connection_eventcb_, c);
        }

        return;
    }

#ifndef EVHTP_DISABLE_SSL
    if (c->ssl && !(events & BEV_EVENT_EOF))
    {
        /* XXX need to do better error handling for SSL specific errors */
        c->error = 1;

        if (c->request)
        {
            c->request->error = 1;
        }
    }
#endif

    if (events == (BEV_EVENT_EOF | BEV_EVENT_READING))
    {
        if (errno == EAGAIN)
        {
            /* libevent will sometimes recv again when it's not actually ready,
             * this results in a 0 return value, and errno will be set to EAGAIN
             * (try again). This does not mean there is a hard socket error, but
             * simply needs to be read again.
             *
             * but libevent will disable the read side of the bufferevent
             * anyway, so we must re-enable it.
             */
            bufferevent_enable(bev, EV_READ);
            errno = 0;

            return;
        }
    }

    c->error     = 1;
    c->connected = 0;

    htp__hook_connection_error_(c, events);

    if (c->paused == 1)
    {
        /* we are currently paused, so we don't want to free just yet, let's
         * wait till the next loop.
         */
        c->free_connection = 1;
    } else {
        evhtp_connection_free((struct evhtp_connection_ *)arg);
    }
} /* htp__connection_eventcb_ */

static struct evhtp_connection_ *
htp__connection_new_(struct evhtp_ * htp, evutil_socket_t sock, evhtp_type type)
{
    struct evhtp_connection_ * connection;
    htp_type                   ptype;

    switch (type) {
        case evhtp_type_client:
            ptype = htp_type_response;
            break;
        case evhtp_type_server:
            ptype = htp_type_request;
            break;
        default:
            return NULL;
    }

    connection = calloc(sizeof(struct evhtp_connection_), 1);
    evhtp_alloc_assert(connection);

    connection->scratch_buf = evbuffer_new();
    evhtp_alloc_assert(connection->scratch_buf);

    connection->error       = 0;
    connection->owner       = 1;
    connection->paused      = 0;
    connection->connected   = 0;
    connection->sock        = sock;
    connection->htp         = htp;
    connection->type        = type;
    connection->parser      = htparser_new();

    evhtp_alloc_assert(connection->parser);

    htparser_init(connection->parser, ptype);
    htparser_set_userdata(connection->parser, connection);

#ifdef EVHTP_FUTURE_USE
    TAILQ_INIT(&connection->pending);
#endif

    return connection;
} /* htp__connection_new_ */

/**
 * @brief pauses a connection (disables reading)
 *
 * @param c a struct evhtp_connection_ * structure
 */
void
evhtp_connection_pause(struct evhtp_connection_ * c)
{
    evhtp_assert(c != NULL);

    c->paused = 1;

    bufferevent_disable(c->bev, EV_READ | EV_WRITE);

    return;
}

/**
 * @brief resumes a connection (enables reading) and activates resume event.
 *
 * @param c
 */
void
evhtp_connection_resume(struct evhtp_connection_ * c)
{
    evhtp_assert(c != NULL);

    c->paused = 0;

    event_active(c->resume_ev, EV_WRITE, 1);

    return;
}

