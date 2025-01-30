#ifndef _NGX_SOCKS5_INCLUDED_H_
#define _NGX_SOCKS5_INCLUDED_H_

#include <ngx_core.h>
#include <ngx_event_connect.h>

#define NGX_SOCKS5_VERSION  0x05
#define NGX_SOCKS5_RESERVED 0x00

#define NGX_SOCKS5_NO_AUTH            0x00
#define NGX_SOCKS5_USR_PWD_AUTH       0x02
#define NGX_SOCKS5_NO_ACCEPTABLE_AUTH 0xFF

#define NGX_SOCKS5_CMD_CONNECT       0x01
#define NGX_SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define NGX_SOCKS5_ATYP_NONE   0xFF
#define NGX_SOCKS5_ATYP_IPV4   0x01
#define NGX_SOCKS5_ATYP_DOMAIN 0x03
#if (NGX_HAVE_INET6)
#define NGX_SOCKS5_ATYP_IPV6   0x04
#endif

#define NGX_SOCKS5_REP_SUCCESS                  0x00
#define NGX_SOCKS5_REP_GENERAL_SRV_FAILURE      0x01
#define NGX_SOCKS5_REP_CONN_DISALLOW_BY_RULESET 0x02
#define NGX_SOCKS5_REP_NET_UNREACHABLE          0x03
#define NGX_SOCKS5_REP_HOST_UNREACHABLE         0x04
#define NGX_SOCKS5_REP_CONN_REFUSED             0x05
#define NGX_SOCKS5_REP_TTL_EXPIRED              0x06
#define NGX_SOCKS5_REP_CMD_UNSUPPORTED          0x07
#define NGX_SOCKS5_REP_ATYP_UNSUPPORTED         0x08

#define NGX_SOCKS5_USR_PWD_AUTH_PASS            0x00

typedef struct {
    ngx_peer_connection_t   *peer;
    ngx_msec_t               timeout;

    ngx_buf_t               *request;
    ngx_buf_t               *response;
    ngx_int_t                res_atyp;
    ngx_pool_t              *pool;

    ngx_flag_t               pass;
} ngx_socks5_conn_ctx_t;

ngx_int_t ngx_socks5_context_init(ngx_socks5_conn_ctx_t *, ngx_peer_connection_t *, ngx_msec_t);
void ngx_socks5_context_clear(ngx_socks5_conn_ctx_t *);

ngx_int_t ngx_socks5_auth_method_negotiation(ngx_socks5_conn_ctx_t *);
ngx_int_t ngx_socks5_auth_method_selection(ngx_socks5_conn_ctx_t *, ngx_int_t *);

ngx_int_t ngx_socks5_auth_request(ngx_socks5_conn_ctx_t *);
ngx_int_t ngx_socks5_auth_response(ngx_socks5_conn_ctx_t *);

ngx_int_t ngx_socks5_proxy_request(ngx_socks5_conn_ctx_t *);
ngx_int_t ngx_socks5_proxy_response(ngx_socks5_conn_ctx_t *);

ngx_flag_t ngx_socks5_peer_verify(ngx_peer_connection_t *);

#endif
