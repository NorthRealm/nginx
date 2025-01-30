#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_config.h>
#include <ngx_socks5.h>
#include <ngx_stream_socks5_module.h>

static void *ngx_stream_socks5_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_socks5_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t ngx_stream_socks5_create_session(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_socks5_negotiation_phase(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_send_method_message(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_recv_select_method(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_socks5_usr_pwd_subnegotiation_phase(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_send_auth_request(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_recv_auth_response(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_socks5_req_phase(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_send_proxy_request(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_recv_proxy_response(ngx_stream_session_t *s);

static void ngx_stream_socks5_handshake_io_event_handler(ngx_event_t *ev);

static ngx_command_t  ngx_stream_socks5_directives[] = {
    {ngx_string("socks5_timeout"),
     NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_socks5_srv_conf_t, timeout),
     NULL},
    ngx_null_command,
};


static ngx_stream_module_t  ngx_stream_socks5_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_socks5_create_srv_conf,     /* create server configuration */
    ngx_stream_socks5_merge_srv_conf       /* merge server configuration */
};

ngx_module_t ngx_stream_socks5_module = {
    NGX_MODULE_V1,
    &ngx_stream_socks5_module_ctx,         /* module context */
    ngx_stream_socks5_directives,          /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_stream_socks5_create_srv_conf(ngx_conf_t *cf) {
    ngx_stream_socks5_srv_conf_t  *sconf;

    sconf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_socks5_srv_conf_t));

    if (sconf == NULL) {
        return NULL;
    }

    sconf->timeout = NGX_CONF_UNSET_MSEC;

    return sconf;
}

static char *ngx_stream_socks5_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {

    ngx_stream_socks5_srv_conf_t  *upper = prev;
    ngx_stream_socks5_srv_conf_t  *current = conf;

    ngx_conf_merge_msec_value(current->timeout, upper->timeout, 3 * 1000);

    return NGX_CONF_OK;
}

ngx_int_t ngx_stream_socks5_handshake(ngx_stream_session_t *s) {

    ngx_peer_connection_t         *peer;
    ngx_connection_t              *pc;
    ngx_stream_socks5_conn_ctx_t  *ctx;
    ngx_stream_socks5_srv_conf_t  *sconf;
    ngx_int_t                      rc;

    peer = &s->upstream->peer;
    pc = peer->connection;

    rc = NGX_ERROR;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(pc->pool, sizeof(ngx_stream_socks5_conn_ctx_t));

        if (ctx == NULL) {
            ngx_stream_socks5_clear_session(s);
            return NGX_ERROR;
        }

        rc = ngx_socks5_context_init(&ctx->ctx, peer, sconf->timeout);
        if (rc != NGX_OK) {
            ngx_stream_socks5_clear_session(s);
            return NGX_ERROR;
        }

        ctx->handler = ngx_stream_socks5_create_session;
        ngx_stream_set_ctx(s, ctx, ngx_stream_socks5_module);
    }

    rc = ctx->handler(s);

    if (rc == NGX_OK) {
        rc = ctx->ctx.pass ? NGX_DONE : NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        pc->read->handler = ngx_stream_socks5_handshake_io_event_handler;
        pc->write->handler = ngx_stream_socks5_handshake_io_event_handler;
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return rc;
    }

    if (rc == NGX_DONE) {
        peer->use_socks5 = 0;
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_create_session(ngx_stream_session_t *s) {
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    ctx->handler = ngx_stream_socks5_negotiation_phase;

    return ctx->handler(s);
}

static ngx_int_t ngx_stream_socks5_negotiation_phase(ngx_stream_session_t *s) {
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    ctx->handler = ngx_stream_socks5_send_method_message;

    return ctx->handler(s);
}


static ngx_int_t ngx_stream_socks5_send_method_message(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    rc = ngx_socks5_auth_method_negotiation(&ctx->ctx);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ctx->handler = ngx_stream_socks5_recv_select_method;
        return NGX_OK;
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_recv_select_method(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_int_t                      res;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    res = NGX_SOCKS5_NO_ACCEPTABLE_AUTH;

    rc = ngx_socks5_auth_method_selection(&ctx->ctx, &res);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        switch (res) {
            case NGX_SOCKS5_NO_AUTH:
                ctx->handler = ngx_stream_socks5_req_phase;
                break;
            case NGX_SOCKS5_USR_PWD_AUTH:
                ctx->handler = ngx_stream_socks5_usr_pwd_subnegotiation_phase;
                break;
            case NGX_SOCKS5_NO_ACCEPTABLE_AUTH:
            default:
                ngx_stream_socks5_clear_session(s);
                return NGX_ERROR;
        }
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_usr_pwd_subnegotiation_phase(ngx_stream_session_t *s) {
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    ctx->handler = ngx_stream_socks5_send_auth_request;

    return ctx->handler(s);
}

static ngx_int_t ngx_stream_socks5_send_auth_request(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    rc = ngx_socks5_auth_request(&ctx->ctx);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ctx->handler = ngx_stream_socks5_recv_auth_response;
        return NGX_OK;
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_recv_auth_response(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    rc = ngx_socks5_auth_response(&ctx->ctx);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ctx->handler = ngx_stream_socks5_req_phase;
        return NGX_OK;
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_req_phase(ngx_stream_session_t *s) {
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    ctx->handler = ngx_stream_socks5_send_proxy_request;

    return ctx->handler(s);
}

static ngx_int_t ngx_stream_socks5_send_proxy_request(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    rc = ngx_socks5_proxy_request(&ctx->ctx);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ctx->handler = ngx_stream_socks5_recv_proxy_response;
        return NGX_OK;
    }

    return rc;
}

static ngx_int_t ngx_stream_socks5_recv_proxy_response(ngx_stream_session_t *s) {

    ngx_int_t                      rc;
    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    rc = ngx_socks5_proxy_response(&ctx->ctx);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_clear_session(s);
        return NGX_ERROR;
    }

    return rc;
}

void ngx_stream_socks5_clear_session(ngx_stream_session_t *s) {
    ngx_pool_t  *pool;

    ngx_stream_socks5_conn_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ctx == NULL) {
        goto end;
    }

    ngx_socks5_context_clear(&ctx->ctx);

    if (!s->upstream) {
        goto end;
    }

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   s->upstream->peer.log, 0,
                   "clear stream socks5 session: #%uA",
                   s->upstream->peer.connection->number);
#endif

    pool = s->upstream->peer.connection->pool;
    ngx_pfree(pool, ctx);

end:
    ngx_stream_set_ctx(s, NULL, ngx_stream_socks5_module);
}

static void ngx_stream_socks5_handshake_io_event_handler(ngx_event_t *ev) {
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "stream socks5 handshake io event handler: %d", ev->write);

    if (ev->timedout) {
        s->upstream->peer.socks5.handshake_callback(c);
        return;
    }

    if (ngx_stream_socks5_handshake(s) == NGX_AGAIN) {
        return;
    }

    s->upstream->peer.socks5.handshake_callback(c);
}
