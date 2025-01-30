#ifndef _NGX_STREAM_SOCKS5_H_INCLUDED_
#define _NGX_STREAM_SOCKS5_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_upstream.h>
#include <ngx_socks5.h>

typedef ngx_int_t (*ngx_stream_socks5_session_handler_pt)(ngx_stream_session_t *);

typedef struct {
    ngx_socks5_conn_ctx_t                  ctx;
    ngx_stream_socks5_session_handler_pt   handler;
} ngx_stream_socks5_conn_ctx_t;

typedef struct {
    ngx_msec_t                            timeout;
} ngx_stream_socks5_srv_conf_t;

ngx_int_t ngx_stream_socks5_handshake(ngx_stream_session_t *);
void ngx_stream_socks5_clear_session(ngx_stream_session_t *);

extern ngx_module_t  ngx_stream_socks5_module;

#endif
