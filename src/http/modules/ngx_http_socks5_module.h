#ifndef _NGX_HTTP_SOCKS5_H_INCLUDED_
#define _NGX_HTTP_SOCKS5_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_socks5.h>

typedef ngx_int_t (*ngx_http_socks5_session_handler_pt)(ngx_http_request_t *);

typedef struct {
    ngx_socks5_conn_ctx_t                ctx;
    ngx_http_socks5_session_handler_pt   handler;
} ngx_http_socks5_conn_ctx_t;

typedef struct {
    ngx_msec_t                          timeout;
} ngx_http_socks5_srv_conf_t;

ngx_int_t ngx_http_socks5_handshake(ngx_http_request_t *);
void ngx_http_socks5_clear_session(ngx_http_request_t *);

extern ngx_module_t  ngx_http_socks5_module;

#endif
