#include <ngx_socks5.h>

static ngx_core_module_t ngx_event_socks5_module_ctx = {
    ngx_string("event_socks5"),
    NULL,
    NULL
};


ngx_module_t  ngx_event_socks5_module = {
    NGX_MODULE_V1,
    &ngx_event_socks5_module_ctx,   /* module context */
    NULL,                           /* module directives */
    NGX_CORE_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_socks5_context_init(ngx_socks5_conn_ctx_t *ctx, ngx_peer_connection_t *peer, ngx_msec_t timeout) {
    if (!ctx || !peer) {
        return NGX_ERROR;
    }

    ctx->peer = peer;
    ctx->request = NULL;
    ctx->response = NULL;
    ctx->res_atyp = NGX_SOCKS5_ATYP_NONE;

    if (!ctx->pool) {
        ctx->pool = ngx_create_pool(2048, peer->connection->log);
        if (ctx->pool == NULL) {
            return NGX_ERROR;
        }
    }

    ctx->timeout = timeout;

    return NGX_OK;
}

void
ngx_socks5_context_clear(ngx_socks5_conn_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->pool != NULL) {
        ngx_destroy_pool(ctx->pool);
        ctx->pool = NULL;
        ctx->request = NULL;
        ctx->response = NULL;
    }
}

ngx_int_t
ngx_socks5_auth_method_negotiation(ngx_socks5_conn_ctx_t *ctx) {
    ssize_t                 size, n;
    ngx_peer_connection_t  *peer;
    ngx_connection_t       *pc;

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->write->timedout) {
        return NGX_ERROR;
    }

    if (ctx->request == NULL) {
        ctx->request = ngx_create_temp_buf(ctx->pool, 3);

        if (ctx->request == NULL) {
            return NGX_ERROR;
        }

        ctx->request->pos[0] = NGX_SOCKS5_VERSION;
        ctx->request->pos[1] = 0x01;

        ctx->request->pos[2] = (peer->socks5.username != NULL
                                || peer->socks5.password != NULL)
                                ? NGX_SOCKS5_USR_PWD_AUTH : NGX_SOCKS5_NO_AUTH;

        ctx->request->last = ctx->request->pos + 3;

#if (NGX_DEBUG)
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 negotiation (request): "
                                                        "VER: %d, NMETHODS: %d, METHODS: %d",
                                                        ctx->request->start[0],
                                                        ctx->request->start[1],
                                                        ctx->request->start[2]);
#endif
    }

    do {
        size = ctx->request->last - ctx->request->pos;
        if (size == 0) {
            break;
        }

        n = pc->send(pc, ctx->request->pos, size);

        if (n > 0) {
            ctx->request->pos += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    } while (pc->write->ready && size > 0);

    if (ctx->request->last - ctx->request->pos > 0) {
        if (!pc->write->timer_set && ctx->timeout) {
            ngx_add_timer(pc->write, ctx->timeout);
        }

        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_pfree(ctx->pool, ctx->request->start);
    ngx_pfree(ctx->pool, ctx->request);
    ctx->request = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_socks5_auth_method_selection(ngx_socks5_conn_ctx_t *ctx, ngx_int_t *res) {
    ssize_t                 size, n;
    ngx_peer_connection_t  *peer;
    ngx_connection_t       *pc;

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->read->timedout) {
        return NGX_ERROR;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 2);

        if (ctx->response == NULL) {
            return NGX_ERROR;
        }
    }

    do {
        size = ctx->response->end - ctx->response->last;
        if (size == 0) {
            break;
        }

        n = pc->recv(pc, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    } while (pc->read->ready && size > 0);

    if (ngx_buf_size(ctx->response) < 2) {
        if (!pc->read->timer_set && ctx->timeout) {
            ngx_add_timer(pc->read, ctx->timeout);
        }

        if (pc->read->eof) {
            return NGX_ERROR;
        }

        if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (ctx->response->pos[0] != NGX_SOCKS5_VERSION) {
        return NGX_ERROR;
    }

    if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 negotiation (response): "
                                                    "VER: %d, METHOD: %d",
                                                    ctx->response->start[0],
                                                    ctx->response->start[1]);

    *res = ctx->response->pos[1];

    ngx_pfree(ctx->pool, ctx->response->start);
    ngx_pfree(ctx->pool, ctx->response);
    ctx->response = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_socks5_auth_request(ngx_socks5_conn_ctx_t *ctx) {
    ssize_t                 size, n;
    ssize_t                 rl;
    ngx_peer_connection_t  *peer;
    ngx_connection_t       *pc;
    u_char                 *bufpos;

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->write->timedout) {
        return NGX_ERROR;
    }

    bufpos = NULL;

    if (ctx->request == NULL) {
        rl = 1 + 1 + peer->socks5.username->len + 1 + peer->socks5.password->len;

        ctx->request = ngx_create_temp_buf(ctx->pool, rl);

        if (ctx->request == NULL) {
            return NGX_ERROR;
        }

        ctx->request->pos[0] = NGX_SOCKS5_VERSION;

        ctx->request->pos[1] = peer->socks5.username->len;
        bufpos = ngx_cpymem(ctx->request->pos + 2, peer->socks5.username->data, peer->socks5.username->len);

        *(bufpos++) = peer->socks5.password->len;
        bufpos = ngx_cpymem(bufpos, peer->socks5.password->data, peer->socks5.password->len);

        ctx->request->last = bufpos;

        if (ctx->request->last - ctx->request->pos != rl) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 usr pwd subnegotiation (request): "
                                                        "VER: %d, ULEN: %d, PLEN: %d",
                                                        ctx->request->start[0],
                                                        ctx->request->start[1],
                                                        *(ctx->request->last - peer->socks5.password->len));
#endif
    }

    do {
        size = ctx->request->last - ctx->request->pos;
        if (size == 0) {
            break;
        }

        n = pc->send(pc, ctx->request->pos, size);

        if (n > 0) {
            ctx->request->pos += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    } while (pc->write->ready && size > 0);

    if (ctx->request->last - ctx->request->pos > 0) {
        if (!pc->write->timer_set && ctx->timeout) {
            ngx_add_timer(pc->write, ctx->timeout);
        }

        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_pfree(ctx->pool, ctx->request->start);
    ngx_pfree(ctx->pool, ctx->request);
    ctx->request = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_socks5_auth_response(ngx_socks5_conn_ctx_t *ctx) {
    ssize_t                        size, n;
    ngx_peer_connection_t         *peer;
    ngx_connection_t              *pc;

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->read->timedout) {
        return NGX_ERROR;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 2);

        if (ctx->response == NULL) {
            return NGX_ERROR;
        }
    }

    do {
        size = ctx->response->end - ctx->response->last;
        if (size == 0) {
            break;
        }

        n = pc->recv(pc, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    } while (pc->read->ready && size > 0);

    if (ngx_buf_size(ctx->response) < 2) {
        if (!pc->read->timer_set && ctx->timeout) {
            ngx_add_timer(pc->read, ctx->timeout);
        }

        if (pc->read->eof) {
            return NGX_ERROR;
        }

        if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (ctx->response->pos[0] != NGX_SOCKS5_VERSION) {
        return NGX_ERROR;
    }

    if (ctx->response->pos[1] != NGX_SOCKS5_USR_PWD_AUTH_PASS) {
        return NGX_ERROR;
    }

    if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 usr pwd subnegotiation (response): "
                                                    "VER: %d, STATUS: %d",
                                                    ctx->response->start[0],
                                                    ctx->response->start[1]);

    ngx_pfree(ctx->pool, ctx->response->start);
    ngx_pfree(ctx->pool, ctx->response);
    ctx->response = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_socks5_proxy_request(ngx_socks5_conn_ctx_t *ctx) {

    ssize_t                        size, n;
    ssize_t                        rl;
    ngx_peer_connection_t         *peer;
    ngx_connection_t              *pc;
    ngx_uint_t                     i;
    u_char                        *bufpos, raw_ip[16];
    struct sockaddr_in            *raw4;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6           *raw6;
#endif
    ngx_uint_t                     atyp;

    ngx_uint_t                     addrlen;
    in_port_t                      port;

    addrlen = 0;
    port = 0;

#if (NGX_DEBUG)
    u_char v_ip[256];
    ngx_memzero(v_ip, sizeof(v_ip));
#endif

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->write->timedout) {
        return NGX_ERROR;
    }

    bufpos = NULL;

    if (ctx->request == NULL) {

        ngx_memzero(raw_ip, sizeof(raw_ip));

        if (peer->socks5.host) {
            atyp = NGX_SOCKS5_ATYP_DOMAIN;

            rl = 1 + 1 + 1 + 1 + 1 + peer->socks5.host->len + 2;
            ctx->request = ngx_create_temp_buf(ctx->pool, rl);

            if (ctx->request == NULL) {
                return NGX_ERROR;
            }

            ctx->request->pos[0] = NGX_SOCKS5_VERSION;
            ctx->request->pos[1] = NGX_SOCKS5_CMD_CONNECT;
            ctx->request->pos[2] = NGX_SOCKS5_RESERVED;
            ctx->request->pos[3] = atyp;
            ctx->request->pos[4] = peer->socks5.host->len;

            bufpos = ngx_cpymem(ctx->request->pos + 5,
                                peer->socks5.host->data,
                                peer->socks5.host->len);

            port = htons(peer->socks5.port);

#if (NGX_DEBUG)
    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 proxy request: "
                                                    "VER: %d, CMD: %d, "
                                                    "ATYP: %d, DST.ADDR: %V, DST.PORT: %d",
                                                    ctx->request->start[0], ctx->request->start[1],
                                                    ctx->request->start[3], peer->socks5.host, port);
#endif
        } else {
            switch (peer->sockaddr->sa_family) {
                case AF_INET:
                    atyp = NGX_SOCKS5_ATYP_IPV4;
                    raw4 = (struct sockaddr_in *)peer->sockaddr;
                    addrlen = 4;

                    i = 0;

                    // Big endian
                    while (i < addrlen) {
                        raw_ip[i] = (raw4->sin_addr.s_addr >> (i * 8)) & 0xFF;
                        ++i;
                    }

                    port = raw4->sin_port;

#if (NGX_DEBUG)
                    ngx_inet_ntop(AF_INET, &raw4->sin_addr, v_ip, 256);
#endif
                    break;

#if (NGX_HAVE_INET6)
                case AF_INET6:
                    atyp = NGX_SOCKS5_ATYP_IPV6;
                    raw6 = (struct sockaddr_in6 *)peer->sockaddr;
                    addrlen = 16;

                    i = 0;

                    while (i < addrlen) {
                        raw_ip[i] = raw6->sin6_addr.s6_addr[i];
                        ++i;
                    }

                    port = raw6->sin6_port;

#if (NGX_DEBUG)
                    ngx_inet_ntop(AF_INET6, &raw6->sin6_addr, v_ip, 256);
#endif
                    break;
#endif
                default:
                    return NGX_ERROR;
            }

            rl = 1 + 1 + 1 + 1 + addrlen + 2;
            ctx->request = ngx_create_temp_buf(ctx->pool, rl);

            if (ctx->request == NULL) {
                return NGX_ERROR;
            }

            ctx->request->pos[0] = NGX_SOCKS5_VERSION;
            ctx->request->pos[1] = NGX_SOCKS5_CMD_CONNECT;
            ctx->request->pos[2] = NGX_SOCKS5_RESERVED;
            ctx->request->pos[3] = atyp;

            bufpos = ngx_cpymem(ctx->request->pos + 4, raw_ip, addrlen);

#if (NGX_DEBUG)
    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 proxy request: "
                                                    "VER: %d, CMD: %d, "
                                                    "ATYP: %d, DST.ADDR: %s, DST.PORT: %d",
                                                    ctx->request->start[0], ctx->request->start[1],
                                                    ctx->request->start[3], v_ip, htons(port));
#endif
        }
        // Assume port var derived from sin_port is already in Big endian
        *(bufpos++) = (port & 0x00FF);
        *(bufpos++) = (port & 0xFF00) >> 8;

        ctx->request->last = bufpos;

        if (ctx->request->last - ctx->request->pos != rl) {
            return NGX_ERROR;
        }
    }

    do {
        size = ctx->request->last - ctx->request->pos;
        if (size == 0) {
            break;
        }

        n = pc->send(pc, ctx->request->pos, size);

        if (n > 0) {
            ctx->request->pos += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    } while (pc->write->ready && size > 0);

    if (ctx->request->last - ctx->request->pos > 0) {
        if (!pc->write->timer_set && ctx->timeout) {
            ngx_add_timer(pc->write, ctx->timeout);
        }

        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_pfree(ctx->pool, ctx->request->start);
    ngx_pfree(ctx->pool, ctx->request);
    ctx->request = NULL;

    return NGX_OK;
}

ngx_int_t
ngx_socks5_proxy_response(ngx_socks5_conn_ctx_t *ctx) {
    ssize_t                        size, n;
    ngx_peer_connection_t         *peer;
    ngx_connection_t              *pc;

    ngx_int_t                      pass;

#if (NGX_DEBUG)
    u_char                         bnd_raw_ip[16], bnd_domain[256], v_ip[256];
    in_port_t                      bnd_port;

    bnd_port = 0;
#endif

    pass = 0;

    peer = ctx->peer;
    pc = peer->connection;

    if (pc->read->timedout) {
        return NGX_ERROR;
    }

    if (ctx->response == NULL) {
        switch (ctx->res_atyp) {
            case NGX_SOCKS5_ATYP_NONE:
                ctx->response = ngx_create_temp_buf(ctx->pool, 4);
                break;
            case NGX_SOCKS5_ATYP_IPV4:
                ctx->response = ngx_create_temp_buf(ctx->pool, 6);
                break;
#if (NGX_HAVE_INET6)
            case NGX_SOCKS5_ATYP_IPV6:
                ctx->response = ngx_create_temp_buf(ctx->pool, 18);
                break;
#endif
            case NGX_SOCKS5_ATYP_DOMAIN:
                ctx->response = ngx_create_temp_buf(ctx->pool, 1);
                break;
            default:
                return NGX_ERROR;
        }

        if (ctx->response == NULL) {
            return NGX_ERROR;
        }
    }

    do {
        size = ctx->response->end - ctx->response->last;
        if (size == 0) {
            break;
        }

        n = pc->recv(pc, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

    } while (pc->read->ready && size > 0);

    if (ctx->response->last - ctx->response->pos < ctx->response->end - ctx->response->start) {

        if (!pc->read->timer_set && ctx->timeout) {
            ngx_add_timer(pc->read, ctx->timeout);
        }

        if (pc->read->eof) {
            return NGX_ERROR;
        }

        if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    switch (ctx->res_atyp) {

        case NGX_SOCKS5_ATYP_NONE:

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                           "socks5 proxy response: VER: %d, REP: %d, RSV: %d, ATYP: %d",
                           ctx->response->pos[0],
                           ctx->response->pos[1],
                           ctx->response->pos[2],
                           ctx->response->pos[3]);

            if (ctx->response->pos[0] != NGX_SOCKS5_VERSION) {
                return NGX_ERROR;
            }
            if (ctx->response->pos[1] != NGX_SOCKS5_REP_SUCCESS) {

                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "socks5 proxy response: proxy fails, REP: %d",
                              ctx->response->pos[1]);

                return NGX_ERROR;
            }
            if (ctx->response->pos[2] != NGX_SOCKS5_RESERVED) {
                return NGX_ERROR;
            }
            switch (ctx->response->pos[3]) {
                case NGX_SOCKS5_ATYP_DOMAIN:
                    ctx->res_atyp = NGX_SOCKS5_ATYP_DOMAIN;
                    break;
                case NGX_SOCKS5_ATYP_IPV4:
                    ctx->res_atyp = NGX_SOCKS5_ATYP_IPV4;
                    break;
#if (NGX_HAVE_INET6)
                case NGX_SOCKS5_ATYP_IPV6:
                    ctx->res_atyp = NGX_SOCKS5_ATYP_IPV6;
                    break;
#endif
                default:
                    return NGX_ERROR;
            }

            ngx_pfree(ctx->pool, ctx->response->start);
            ngx_pfree(ctx->pool, ctx->response);
            ctx->response = NULL;

            break;

        case NGX_SOCKS5_ATYP_IPV4:
#if (NGX_DEBUG)
            ngx_memzero(bnd_raw_ip, sizeof(bnd_raw_ip));
            ngx_memzero(v_ip, sizeof(v_ip));
            ngx_memcpy(bnd_raw_ip, ctx->response->pos, 4);
            bnd_port = ((in_port_t)ctx->response->pos[5] << 8);
            bnd_port += ctx->response->pos[4];

            ngx_inet_ntop(AF_INET, bnd_raw_ip, v_ip, 256);
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 proxy response: "
                                                            "BND.ADDR: %s, BND.PORT: %d",
                                                            v_ip, htons(bnd_port));
#endif
            pass = 1;

            break;

#if (NGX_HAVE_INET6)
        case NGX_SOCKS5_ATYP_IPV6:
#if (NGX_DEBUG)
            ngx_memzero(bnd_raw_ip, sizeof(bnd_raw_ip));
            ngx_memzero(v_ip, sizeof(v_ip));
            ngx_memcpy(bnd_raw_ip, ctx->response->pos, 16);
            bnd_port = ((in_port_t)ctx->response->pos[17] << 8);
            bnd_port += ctx->response->pos[16];

            ngx_inet_ntop(AF_INET6, bnd_raw_ip, v_ip, 256);
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 proxy response: "
                                                            "BND.ADDR: %s, BND.PORT: %d",
                                                            v_ip, htons(bnd_port));
#endif
            pass = 1;

            break;
#endif
        case NGX_SOCKS5_ATYP_DOMAIN:
            size = ngx_buf_size(ctx->response);
            if (size <= 0) {
                return NGX_ERROR;
            }

            if (size == 1) {

                n = ctx->response->pos[0];
                ngx_pfree(ctx->pool, ctx->response->start);
                ngx_pfree(ctx->pool, ctx->response);

                ctx->response = ngx_create_temp_buf(ctx->pool, n + 2);

                if (ctx->response == NULL) {
                    return NGX_ERROR;
                }

            } else {
#if (NGX_DEBUG)
                ngx_memzero(bnd_domain, size);
                ngx_memcpy(bnd_domain, ctx->response->pos, size - 2);
                bnd_port = ((in_port_t)ctx->response->pos[size - 1] << 8);
                bnd_port += ctx->response->pos[size - 2];

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "socks5 proxy response: "
                                                                "BND.ADDR: %s, BND.PORT: %d",
                                                                bnd_domain, htons(bnd_port));
#endif
                pass = 1;
            }

            break;

        default:
            return NGX_ERROR;
    }

    if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pass) {
        ctx->pass = 1;
        return NGX_OK;
    }

    return NGX_AGAIN;
}

ngx_flag_t ngx_socks5_peer_verify(ngx_peer_connection_t *peer) {
    int type;

    type = peer->type ? peer->type : SOCK_STREAM;

    return (peer->socks5.sockaddr != NULL
            && type == SOCK_STREAM
            && peer->sockaddr->sa_family != AF_UNIX);
}
