#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

struct htp__io_buf {
    struct evbuffer * io_buf_in;        /**< buffer containing data from client */
    struct evbuffer * io_buf_out;       /**< buffer containing data to client */
};

/**
 * @brief a structure containing all information for a http request.
 */
struct evhtp_request_ {
    evhtp_t            * req_htp;       /**< the parent evhtp_t structure */
    evhtp_connection_t * req_conn;      /**< the associated connection */
    evhtp_hooks_t      * req_hooks;     /**< request specific hooks */
    evhtp_uri_t        * req_uri;       /**< request URI information */
    evhtp_headers_t    * headers_in;    /**< headers from client */
    evhtp_headers_t    * headers_out;   /**< headers to client */
    evhtp_proto          proto;         /**< HTTP protocol used */
    htp_method           method;        /**< HTTP method used */
    evhtp_res            status;        /**< The HTTP response code or other error conditions */
    uint8_t              keepalive : 1, /**< set to 1 if the connection is keep-alive */
                         finished  : 1, /**< set to 1 if the request is fully processed */
                         chunked   : 1, /**< set to 1 if the request is chunked */
                         error     : 1, /**< set if any sort of error has occurred. */
                         pad       : 4; /**< to be used in evhtp2 for new stuff */

    evhtp_callback_cb cb;               /**< the function to call when fully processed */
    void            * cbarg;            /**< argument which is passed to the cb function */

    TAILQ_ENTRY(evhtp_request_s) next;
};

static htp_method
htp__request_method(struct evhtp_request_ * r)
{
    evhtp_assert(r != NULL);
    evhtp_assert(r->conn != NULL);
    evhtp_assert(r->conn->parser != NULL);

    return htparser_get_method(r->conn->parser);
}

/**
 * @brief Wrapper around evhtp_connection_pause
 *
 * @see evhtp_connection_pause
 *
 * @param request
 */
static void
htp__request_pause(struct evhtp_request_ * request)
{
    evhtp_assert(request != NULL);

    request->status = EVHTP_RES_PAUSE;
    evhtp_connection_pause(request->conn);
}

/**
 * @brief Wrapper around evhtp_connection_resume
 *
 * @see evhtp_connection_resume
 *
 * @param request
 */
void
evhtp_request_resume(struct evhtp_request_ * request)
{
    evhtp_assert(request != NULL);

    evhtp_connection_resume(request->conn);
}

