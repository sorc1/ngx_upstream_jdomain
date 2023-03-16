/*
 * this module (C) wudaike
 * this module (C) Baidu, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define NGX_JDOMAIN_STATUS_DONE 0
#define NGX_JDOMAIN_STATUS_WAIT 1

#ifndef ngx_sync_file
#define ngx_sync_file fsync
#endif

typedef struct {
	struct sockaddr	sockaddr;
	struct sockaddr_in6	padding;

	socklen_t	socklen;

	ngx_str_t	name;
	u_char		ipstr[NGX_SOCKADDR_STRLEN + 1];

#if (NGX_HTTP_SSL)
	ngx_ssl_session_t	*ssl_session;   /* local to a process */
#endif
} ngx_http_upstream_jdomain_peer_t;

typedef struct ngx_http_upstream_jdomain_srv_conf {
	ngx_http_upstream_jdomain_peer_t		*peers;
	ngx_uint_t		default_port;

	ngx_uint_t		resolved_max_ips;
	ngx_uint_t		resolved_num;
	ngx_str_t		resolved_domain;
	ngx_int_t		resolved_status;
	ngx_uint_t		resolved_index;
	time_t 			resolved_access;
	time_t			resolved_interval;

	ngx_uint_t		upstream_retry;
	ngx_str_t		upstream_backup_file;
	ngx_str_t		upstream_temp_backup_dir;
	ngx_uint_t		upstream_backup_fsync:1;

	ngx_resolver_t	*resolver;
	ngx_msec_t		resolver_timeout;

	struct ngx_http_upstream_jdomain_srv_conf *next;
} ngx_http_upstream_jdomain_srv_conf_t;

typedef struct {
	struct ngx_http_upstream_jdomain_srv_conf	*urcf_first;
} ngx_http_upstream_jdomain_main_conf_t;

typedef struct {
	ngx_http_upstream_jdomain_srv_conf_t	*conf;
	ngx_http_core_loc_conf_t 		*clcf;
	
	ngx_int_t			current;

} ngx_http_upstream_jdomain_peer_data_t;

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void* ngx_http_upstream_jdomain_create_main_conf(ngx_conf_t *cf);

static char *ngx_http_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd,
	void *conf);

static char *ngx_http_upstream_jdomain_resolver(ngx_conf_t *cf,
	ngx_command_t *cmd, void *conf);

static void * ngx_http_upstream_jdomain_create_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_upstream_jdomain_init(ngx_conf_t *cf, 
	ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_jdomain_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_upstream_jdomain_init_peer(ngx_http_request_t *r,
	ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_jdomain_get_peer(ngx_peer_connection_t *pc,
	void *data);

static void ngx_http_upstream_jdomain_free_peer(ngx_peer_connection_t *pc,
	void *data, ngx_uint_t state);

static void ngx_http_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx);

static ngx_command_t  ngx_http_upstream_jdomain_commands[] = {
	{ngx_string("jdomain"),
	 NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
	 ngx_http_upstream_jdomain,
	 NGX_HTTP_SRV_CONF_OFFSET,
	 0,
	 NULL },

	{ngx_string("jdomain_resolver"),
	 NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
	 ngx_http_upstream_jdomain_resolver,
	 NGX_HTTP_SRV_CONF_OFFSET,
	 0,
	 NULL },

	{ngx_string("jdomain_resolver_timeout"),
	 NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
	 ngx_conf_set_msec_slot,
	 NGX_HTTP_SRV_CONF_OFFSET,
	 offsetof(ngx_http_upstream_jdomain_srv_conf_t, resolver_timeout),
	 NULL },

	 ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_jdomain_module_ctx = {
	NULL,						/* preconfiguration */
	NULL,						/* postconfiguration */

	ngx_http_upstream_jdomain_create_main_conf,	/* create main configuration */
	NULL,						/* init main configuration */

	ngx_http_upstream_jdomain_create_conf,		/* create server configuration */
	NULL,						/* merge server configuration */

	NULL,						/* create location configuration */
	NULL						/* merge location configuration */
};


ngx_module_t  ngx_http_upstream_jdomain_module = {
	NGX_MODULE_V1,
	&ngx_http_upstream_jdomain_module_ctx,		/* module context */
	ngx_http_upstream_jdomain_commands,		/* module directives */
	NGX_HTTP_MODULE,				/* module type */
	NULL,						/* init master */
	NULL,						/* init module */
	ngx_http_upstream_jdomain_init_process,	/* init process */
	NULL,						/* init thread */
	NULL,						/* exit thread */
	NULL,						/* exit process */
	NULL,						/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_upstream_jdomain_dump_peers(ngx_http_upstream_jdomain_srv_conf_t *urcf, ngx_log_t *log)
{
	ngx_uint_t i;
	u_char buf[ngx_pagesize], *buf_pos, *buf_last;
	ssize_t buf_len;
	u_char tempfile[ngx_pagesize], *tempfile_pos, *tempfile_last;
	ssize_t tempfile_len;
	ngx_file_t file;

	if (urcf->upstream_temp_backup_dir.len == 0 || urcf->upstream_backup_file.len == 0) {
		return NGX_OK;
	}

	ngx_memzero(&file, sizeof(ngx_file_t));
	file.fd = NGX_INVALID_FILE;
	file.log = log;
	file.name = urcf->upstream_backup_file;

	*tempfile = '\0';
	tempfile_pos = tempfile;
	tempfile_last = tempfile + sizeof(tempfile) - 1;
	tempfile_len = 0;

	if (urcf->resolved_num == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"upstream_jdomain_dump_peers: there are no peers to dump");
		goto error;
	}

	tempfile_pos = ngx_snprintf(tempfile_pos, tempfile_last - tempfile_pos, "%V/jdomain_%V_%d.tmp%Z", 
		&urcf->upstream_temp_backup_dir, &urcf->resolved_domain, (unsigned)getpid());
	tempfile_len = tempfile_pos - tempfile;

	file.fd = ngx_open_file(tempfile,
						NGX_FILE_TRUNCATE,
						NGX_FILE_WRONLY,
						NGX_FILE_DEFAULT_ACCESS);
	if (file.fd == NGX_INVALID_FILE) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "upstream_jdomain_dump_peers: "
						"open dump file \"%s\" failed",
						tempfile);
		goto error;
	}

	*buf = '\0';
	buf_pos = buf;
	buf_last = buf + sizeof(buf) - 1;
	buf_len = 0;

	buf_pos = ngx_snprintf(buf_pos, buf_last - buf_pos, 
							"# domain %V\n", 
							&urcf->resolved_domain);
	for (i = 0; i < urcf->resolved_num; i++) {
		ngx_http_upstream_jdomain_peer_t *peer;

		peer = &urcf->peers[i];

		buf_pos = ngx_snprintf(buf_pos, buf_last - buf_pos,
								"server %V;\n", &peer->name);
	}

	buf_len = buf_pos - buf;

	if (ngx_write_file(&file, buf, buf_len, 0) != buf_len) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "upstream_jdomain_dump_peers: "
							"write file failed %V",
							&urcf->upstream_backup_file);
		goto error;
	}

	if (urcf->upstream_backup_fsync) {
		ngx_sync_file(file.fd);
	}

	ngx_close_file(file.fd);
	file.fd = NGX_INVALID_FILE;

	if (ngx_rename_file(tempfile, urcf->upstream_backup_file.data) != 0) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "upstream_jdomain_dump_peers: "
				"renaming \"%s\" to \"%V\" failed",
				tempfile, &urcf->upstream_backup_file);
		goto error;
	}

	ngx_log_error(NGX_LOG_NOTICE, log, 0, "upstream_jdomain_dump_peers: "
				"dump conf file \"%V\" succeeded, number of peers is %d",
				&urcf->upstream_backup_file, urcf->resolved_num);
	return NGX_OK;

error:
	if (file.fd != NGX_INVALID_FILE) {
		ngx_close_file(file.fd);
		file.fd = NGX_INVALID_FILE;
	}

	if (tempfile_len > 0) {
		ngx_delete_file(tempfile);
	}

	return NGX_ERROR;
}

static ngx_int_t
ngx_http_upstream_jdomain_load_peers(ngx_http_upstream_jdomain_srv_conf_t *urcf, ngx_pool_t *pool, ngx_log_t *log)
{
	ngx_uint_t i;
	ssize_t buf_len;
	char buf[ngx_pagesize], *buf_pos;
	char *line_end, *line_pos;
	ngx_uint_t line_len;
	ngx_file_t file;

	if (urcf->upstream_backup_file.len == 0) {
		return NGX_OK;
	}
	if (urcf->resolved_num != 0) {
		return NGX_OK;
	}

	ngx_memzero(&file, sizeof(ngx_open_file_t));
	file.log = log;
	file.name = urcf->upstream_backup_file;
	file.fd = ngx_open_file(urcf->upstream_backup_file.data,
										NGX_FILE_OPEN,
										NGX_FILE_RDONLY,
										NGX_FILE_DEFAULT_ACCESS);
	if (file.fd == NGX_INVALID_FILE) {
		if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOPATH) {
			return NGX_OK;
		}
		ngx_log_error(NGX_LOG_ERR, log, 0,
				"upstream_jdomain_load_peers: opening dump file \"%V\" failed",
				&urcf->upstream_backup_file);
		goto error;
	}

	buf_len = ngx_read_file(&file, (u_char *)buf, sizeof(buf) - 2, 0);
	if (buf_len <= 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
				"upstream_jdomain_load_peers: reading dump file \"%V\" failed",
				&urcf->upstream_backup_file);
		goto error;
	}
	buf[buf_len] = '\n';
	buf[buf_len+1] = '\0';

	ngx_close_file(file.fd);

	buf_pos = buf;
	if (strlen(buf_pos) <= sizeof("# domain ") - 1 || 
		ngx_strncmp(buf_pos, "# domain ", sizeof("# domain ") - 1) != 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "upstream_jdomain_load_peers: \"%V\": "
				"syntax error near %.10s, expected \"# domain \"",
				&urcf->upstream_backup_file, buf_pos);
		goto error;
	}
	buf_pos += sizeof("# domain ") - 1;

	if (strlen(buf_pos) < urcf->resolved_domain.len || 
		ngx_strncmp(buf_pos, urcf->resolved_domain.data, 
			urcf->resolved_domain.len) != 0 ||
		buf_pos[urcf->resolved_domain.len] != '\n') {
		ngx_log_error(NGX_LOG_ERR, log, 0,
				"upstream_jdomain_load_peers: \"%V\" domain name mismatch",
				&urcf->upstream_backup_file);
		goto error;
	}
	buf_pos += urcf->resolved_domain.len + 1;

	for (; (line_end = strchr(buf_pos, '\n')) != NULL; buf_pos = line_end + 1) {
		struct sockaddr *addr;
		ngx_http_upstream_jdomain_peer_t *peer;
		ngx_url_t u;

		peer = &urcf->peers[urcf->resolved_num];
		addr = &peer->sockaddr;

		*line_end = '\0';
		line_len = (ngx_uint_t)(line_end - buf_pos);
		line_pos = buf_pos;

		if (line_len == 0) {
			continue;
		}
		if (*line_pos == '#') {
			continue;
		}
		if (line_len <= sizeof("server ") - 1 || 
			ngx_strncmp(line_pos, "server ", sizeof("server ") - 1) != 0) {
			continue;
		}

		line_pos += sizeof("server ") - 1;
		line_len -= sizeof("server ") - 1;
		while (*line_pos == ' ') {
			line_pos++, line_len--;
		}

		if (line_len == 0) {
			continue;
		}

		for (i = 0; i <= line_len; i++) {
			if (i == NGX_SOCKADDR_STRLEN) {
				break;
			}
			if (line_pos[i] == '\0' || line_pos[i] == ' ' || line_pos[i] == ';') {
				break;
			}
			peer->ipstr[i] = line_pos[i];
		}
		peer->ipstr[i] = '\0';

		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.data = peer->ipstr;
		u.url.len = strlen((char *)peer->ipstr);
		u.default_port = (in_port_t)urcf->default_port;
		u.no_resolve = 1;

		if (ngx_parse_url(pool, &u) != NGX_OK) {
			if (u.err) {
				ngx_log_error(NGX_LOG_EMERG, log, 0,
					"upstream_jdomain_load_peers: %s in upstream \"%V\"", u.err, &u.url);
			}
			continue;
		}
		if (u.naddrs == 0) {
			continue;
		}

		ngx_memcpy(addr, u.addrs[0].sockaddr, u.addrs[0].socklen);

#if (nginx_version) < 1005008
		if (addr->sa_family != AF_INET) {
			continue;
		}
		((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
#else
		peer->socklen = u.addrs[0].socklen;

		switch (addr->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
			break;
		default:
			((struct sockaddr_in*)addr)->sin_port = htons((u_short) urcf->default_port);
		}
#endif
		peer->name.data = peer->ipstr;
		peer->name.len =
#if (nginx_version) <= 1005002
			ngx_sock_ntop(addr, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(addr, peer->socklen, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		ngx_log_error(NGX_LOG_NOTICE, log, 0,
				"upstream_jdomain_load_peers: adding peer %s", peer->ipstr);

		urcf->resolved_num++;
		if (urcf->resolved_num == urcf->resolved_max_ips) {
			break;
		}
	}

	ngx_log_error(NGX_LOG_NOTICE, log, 0, "upstream_jdomain_dump_peers: "
				"dump conf file %V succeeded, number of peers is %d",
				&urcf->upstream_backup_file, urcf->resolved_num);
	return NGX_OK;

error:
	if (file.fd != NGX_INVALID_FILE) {
		ngx_close_file(file.fd);
		file.fd = NGX_INVALID_FILE;
	}
	return NGX_ERROR;
}

static ngx_int_t
ngx_http_upstream_jdomain_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_jdomain_main_conf_t	*jmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_jdomain_module);
	ngx_http_upstream_jdomain_srv_conf_t	*urcf, *urcf_next;

	us->peer.init = ngx_http_upstream_jdomain_init_peer;

	urcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_jdomain_module);

	if (urcf->resolver == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no jdomain resolver");
		return NGX_ERROR;
	}
	if (urcf->resolver_timeout == NGX_CONF_UNSET_MSEC) {
		urcf->resolver_timeout = 30000;
	}
	urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;

	urcf_next = jmcf->urcf_first;
	jmcf->urcf_first = urcf;
	urcf->next = urcf_next;

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_jdomain_init_peer(ngx_http_request_t *r,
	ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_jdomain_peer_data_t	*urpd;
	ngx_http_upstream_jdomain_srv_conf_t	*urcf;

	urcf = ngx_http_conf_upstream_srv_conf(us,
					ngx_http_upstream_jdomain_module);
	
	urpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_jdomain_peer_data_t));
	if(urpd == NULL) {
		return NGX_ERROR;
	}
	
	urpd->conf = urcf;
	urpd->clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	urpd->current = -1;
	
	r->upstream->peer.data = urpd;
	r->upstream->peer.free = ngx_http_upstream_jdomain_free_peer;
	r->upstream->peer.get = ngx_http_upstream_jdomain_get_peer;

	if(urcf->upstream_retry){
		r->upstream->peer.tries = (urcf->resolved_num != 1) ? urcf->resolved_num : 2;
	}else{
		r->upstream->peer.tries = 1;
	}

#if (NGX_HTTP_SSL)
	r->upstream->peer.set_session =
	                       ngx_http_upstream_set_jdomain_peer_session;
	r->upstream->peer.save_session =
                               ngx_http_upstream_save_jdomain_peer_session;
#endif

	return NGX_OK;
}

static void
ngx_http_upstream_jdomain_resolve_start(
	ngx_http_upstream_jdomain_srv_conf_t *urcf, ngx_resolver_t *resolver,
	ngx_msec_t resolver_timeout, ngx_log_t *log)
{
	ngx_resolver_ctx_t	*ctx;

	if(urcf->resolved_status == NGX_JDOMAIN_STATUS_WAIT){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
			"upstream_jdomain: resolving"); 
		return;
	}

	if(ngx_time() <= urcf->resolved_access + urcf->resolved_interval){
		return;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"upstream_jdomain: update from DNS cache"); 

	ctx = resolver ? ngx_resolve_start(resolver, NULL) : NGX_NO_RESOLVER;
	if(ctx == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
			"upstream_jdomain: resolve_start fail"); 
		return;
	}

	if(ctx == NGX_NO_RESOLVER) {
		ngx_log_error(NGX_LOG_ALERT, log, 0,
			"upstream_jdomain: no resolver"); 
		return;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"upstream_jdomain: resolve_start ok"); 

	ctx->name = urcf->resolved_domain;
#if (nginx_version) < 1005008
	ctx->type = NGX_RESOLVE_A;
#endif
	ctx->handler = ngx_http_upstream_jdomain_handler;
	ctx->data = urcf;
	ctx->timeout = resolver_timeout;

	urcf->resolved_status = NGX_JDOMAIN_STATUS_WAIT;
	if(ngx_resolve_name(ctx) != NGX_OK) {
		ngx_log_error(NGX_LOG_ALERT, log, 0,
			"upstream_jdomain: resolve name \"%V\" fail", &ctx->name);
		urcf->resolved_access = ngx_time();
		urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
	}
}

static ngx_int_t
ngx_http_upstream_jdomain_get_peer(ngx_peer_connection_t *pc, void *data)
{
	ngx_http_upstream_jdomain_peer_data_t	*urpd = data;
	ngx_http_upstream_jdomain_srv_conf_t	*urcf = urpd->conf;
	ngx_http_upstream_jdomain_peer_t		*peer;

	pc->cached = 0;
	pc->connection = NULL;

	ngx_http_upstream_jdomain_resolve_start(urcf,
		urcf->resolver,
		urcf->resolver_timeout,
		pc->log);

	/* If the resolution failed during startup or if resolution returned no entries,
	   fail all requests until it recovers */
	if (urcf->resolved_num == 0) {
		ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
			"upstream_jdomain: no resolved entry for \"%V\" fail", &urcf->resolved_domain);
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"upstream_jdomain: resolved_num=%ud", urcf->resolved_num); 

	if(urpd->current == -1){
		urcf->resolved_index = (urcf->resolved_index + 1) % urcf->resolved_num;

		urpd->current = urcf->resolved_index;
	}else{
		urpd->current = (urpd->current + 1) % urcf->resolved_num;
	}

	peer = &(urcf->peers[urpd->current]);

	pc->sockaddr = &peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"upstream_jdomain: upstream to DNS peer (%s:%ud)",
		inet_ntoa(((struct sockaddr_in*)(pc->sockaddr))->sin_addr),
		ntohs((unsigned short)((struct sockaddr_in*)(pc->sockaddr))->sin_port));

	return NGX_OK;
}

static void
ngx_http_upstream_jdomain_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state)
{
	if(pc->tries > 0)
		pc->tries--;
}

static char *
ngx_http_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_srv_conf_t  *uscf;
	ngx_http_upstream_jdomain_srv_conf_t *urcf = conf;

#if (nginx_version) >= 1007003
	ngx_http_upstream_server_t	*us;
#endif

	time_t			interval;
	ngx_str_t		*value, domain, s, backup_file, temp_backup_dir;
	ngx_int_t		default_port, max_ips;
	ngx_uint_t		retry, fail;
	ngx_http_upstream_jdomain_peer_t		*paddr;
	ngx_url_t		u;
	ngx_uint_t		i;
	ngx_uint_t		backup_fsync;

	interval = 1;
	default_port = 80;
	max_ips = 20;
	retry = 1;
	fail = 1;
	domain.data = NULL;
	domain.len = 0;
	backup_file.data = NULL;
	backup_file.len = 0;
	temp_backup_dir.data = NULL;
	temp_backup_dir.len = 0;
	backup_fsync = 0;

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	/*Just For Padding,upstream{} need it*/
	if(uscf->servers == NULL) {
		uscf->servers = ngx_array_create(cf->pool, 1,
	                                     sizeof(ngx_http_upstream_server_t));
		if(uscf->servers == NULL) {
			return NGX_CONF_ERROR;
		}
	}

#if (nginx_version) >= 1007003
	us = ngx_array_push(uscf->servers);
	if (us == NULL) {
		return NGX_CONF_ERROR;
	}
	ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
#endif
	
	uscf->peer.init_upstream = ngx_http_upstream_jdomain_init;

	value = cf->args->elts;

	for (i=2; i < cf->args->nelts; i++) {
		if (value[i].len >= 5 && ngx_strncmp(value[i].data, "port=", 5) == 0) {
			default_port = ngx_atoi(value[i].data+5, value[i].len - 5);

			if ( default_port == NGX_ERROR || default_port < 1 ||
							default_port > 65535) {
				goto invalid;
			}

			continue;
		}

		if (value[i].len >= 9 && ngx_strncmp(value[i].data, "interval=", 9) == 0) {
			s.len = value[i].len - 9;
			s.data = &value[i].data[9];
			
			interval = ngx_parse_time(&s, 1);
			
			if (interval == (time_t) NGX_ERROR) {
				goto invalid;
			}
			
			continue;
		}

		if (value[i].len >= 8 && ngx_strncmp(value[i].data, "max_ips=", 8) == 0) {
			max_ips = ngx_atoi(value[i].data + 8, value[i].len - 8);

			if ( max_ips == NGX_ERROR || max_ips < 1) {
				goto invalid;
			}

			continue;
		}

		if (value[i].len == 9 && ngx_strncmp(value[i].data, "retry_off", 9) == 0) {
			retry = 0;

			continue;
		}

		if (ngx_strncmp(value[i].data, "no_fail", 7) == 0) {
			fail = 0;

			continue;
		}

		if (ngx_strncmp(value[i].data, "backup_file=", 12) == 0) {
			backup_file.len = value[i].len - 12;
			backup_file.data = &value[i].data[12];

			continue;
		}

		if (ngx_strncmp(value[i].data, "temp_backup_dir=", 16) == 0) {
			temp_backup_dir.len = value[i].len - 16;
			temp_backup_dir.data = &value[i].data[16];

			continue;
		}

		if (ngx_strncmp(value[i].data, "backup_fsync", 12) == 0) {
			backup_fsync = 1;

			continue;
		}


		goto invalid;

	}

	domain.data = value[1].data;
	domain.len  = value[1].len;

	urcf->peers = ngx_pcalloc(cf->pool,
			max_ips * sizeof(ngx_http_upstream_jdomain_peer_t));

	if (urcf->peers == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"ngx_palloc peers fail");

		return NGX_CONF_ERROR;
	}

	if (backup_file.len == 0) {
		temp_backup_dir.len = 0;
		temp_backup_dir.data = NULL;
	}

	urcf->resolved_interval = interval;
	urcf->resolved_domain = domain;
	urcf->default_port = default_port;
	urcf->resolved_max_ips = max_ips;
	urcf->upstream_retry = retry;
	urcf->upstream_backup_file = backup_file;
	urcf->upstream_temp_backup_dir = temp_backup_dir;
	urcf->upstream_backup_fsync = backup_fsync;

	urcf->resolved_num = 0;
	/*urcf->resolved_index = 0;*/
	urcf->resolved_access = 0;

	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = value[1];
	u.default_port = (in_port_t) urcf->default_port;

	// in no-fail (fail=0) mode, perform two-pass URL parsing:
	// validate upstream URL on the first pass and exit on error
	// perform domain name resolution on the second pass with jdomain_resolver
	// by each worker in ngx_http_upstream_jdomain_init_process() but do *not*
	// exit with error on failure
	//
	// in default (fail=1) mode, skip the first pass, resolve with the system
	// resolver immediatelly and exit on error
	u.no_resolve = !fail;
	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"%s in upstream \"%V\"", u.err, &u.url);
		}
		return NGX_CONF_ERROR;
	}

	for(i = 0; i < u.naddrs ;i++){
		paddr = &urcf->peers[urcf->resolved_num];
		ngx_memcpy(&paddr->sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);
		paddr->socklen = u.addrs[i].socklen; 

		paddr->name.data = paddr->ipstr;
		paddr->name.len = 
#if (nginx_version) <= 1005002
			ngx_sock_ntop(&paddr->sockaddr, paddr->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(&paddr->sockaddr, paddr->socklen, paddr->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		urcf->resolved_num++;

		if (urcf->resolved_num >= urcf->resolved_max_ips)
			break;
	}

	if (u.naddrs > 0 && !u.no_resolve) {
		urcf->resolved_access = ngx_time();
		ngx_http_upstream_jdomain_dump_peers(urcf, cf->log);
	}
	else if (ngx_http_upstream_jdomain_load_peers(urcf, cf->temp_pool, cf->log) != NGX_OK) {
		if (fail) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;

invalid:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"invalid parameter \"%V\"", &value[i]);

	return NGX_CONF_ERROR;
}

static char *
ngx_http_upstream_jdomain_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_jdomain_srv_conf_t *urcf = conf;
	ngx_str_t  *value;

	if (urcf->resolver) {
		return "is duplicate";
	}

	value = cf->args->elts;

	urcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
	if (urcf->resolver == NULL) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static void *
ngx_http_upstream_jdomain_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_upstream_jdomain_main_conf_t	*jmcf;

	jmcf = ngx_pcalloc(cf->pool, sizeof(*jmcf));
	if (jmcf == NULL) {
		return NULL;
	}

	return jmcf;
}

static void *
ngx_http_upstream_jdomain_create_conf(ngx_conf_t *cf)
{
	ngx_http_upstream_jdomain_srv_conf_t	*conf;

	conf = ngx_pcalloc(cf->pool,
			sizeof(ngx_http_upstream_jdomain_srv_conf_t));
	if (conf == NULL) {
		return NULL;
	}
	conf->resolver_timeout = NGX_CONF_UNSET_MSEC;

	return conf;
}

static void
ngx_http_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx)
{
	struct sockaddr		*addr;
	ngx_uint_t		i;
	ngx_resolver_t		*r;
	ngx_http_upstream_jdomain_peer_t		*peer;
	ngx_http_upstream_jdomain_srv_conf_t	*urcf = ctx->data;

	r = ctx->resolver;

	ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
			"upstream_jdomain: \"%V\" resolved state(%i: %s)",
			&ctx->name, ctx->state,
			ngx_resolver_strerror(ctx->state));

	if (ctx->state || ctx->naddrs == 0) {
		ngx_log_error(NGX_LOG_ERR, r->log, 0,
			"upstream_jdomain: resolver failed ,\"%V\" (%i: %s))",
			&ctx->name, ctx->state,
			ngx_resolver_strerror(ctx->state));

		goto end;
	}

	urcf->resolved_num = 0;

	for (i = 0; i < ctx->naddrs; i++) {

		peer = &urcf->peers[urcf->resolved_num];
		addr = &peer->sockaddr;

#if (nginx_version) < 1005008
		peer->socklen = sizeof(struct sockaddr);

		((struct sockaddr_in*)addr)->sin_family = AF_INET;
		((struct sockaddr_in*)addr)->sin_addr.s_addr = ctx->addrs[i];
		((struct sockaddr_in*)addr)->sin_port = htons(urcf->default_port);
#else
		peer->socklen = ctx->addrs[i].socklen;

		ngx_memcpy(addr, ctx->addrs[i].sockaddr, peer->socklen);

		switch (addr->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
			break;
		default:
			((struct sockaddr_in*)addr)->sin_port = htons((u_short) urcf->default_port);
		}

#endif
		peer->name.data = peer->ipstr;
		peer->name.len = 
#if (nginx_version) <= 1005002
			ngx_sock_ntop(addr, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(addr, peer->socklen, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		urcf->resolved_num++;

		if( urcf->resolved_num >= urcf->resolved_max_ips)
			break;
	}

	ngx_http_upstream_jdomain_dump_peers(urcf, r->log);

end:
	ngx_resolve_name_done(ctx);

	urcf->resolved_access = ngx_time();
	urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
}

static ngx_int_t
ngx_http_upstream_jdomain_init_process(ngx_cycle_t *cycle)
{
	ngx_http_upstream_jdomain_main_conf_t	*jmcf;
	ngx_http_upstream_jdomain_srv_conf_t	*urcf;
	ngx_pool_t *temp_pool;

	ngx_time_update();

	temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
	if (temp_pool == NULL) {
		return NGX_ERROR;
	}

	jmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_jdomain_module);
	for (urcf = jmcf->urcf_first; urcf != NULL; urcf = urcf->next) {
		ngx_http_upstream_jdomain_load_peers(urcf, temp_pool, cycle->log);

		if (urcf->resolved_num > 0)
			continue;

		ngx_http_upstream_jdomain_resolve_start(urcf,
			urcf->resolver, urcf->resolver_timeout, cycle->log);
	}
	ngx_destroy_pool(temp_pool);

	return NGX_OK;
}

#if (NGX_HTTP_SSL)

ngx_int_t
ngx_http_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc,
	void *data)
{
	ngx_http_upstream_jdomain_peer_data_t  *urpd = data;

	ngx_int_t                     rc;
	ngx_ssl_session_t            *ssl_session;
	ngx_http_upstream_jdomain_peer_t  *peer;

	peer = &urpd->conf->peers[urpd->current];

	ssl_session = peer->ssl_session;

	rc = ngx_ssl_set_session(pc->connection, ssl_session);

	return rc;
}


void
ngx_http_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc,
	void *data)
{
	ngx_http_upstream_jdomain_peer_data_t  *urpd = data;

	ngx_ssl_session_t            *old_ssl_session, *ssl_session;
	ngx_http_upstream_jdomain_peer_t  *peer;

	ssl_session = ngx_ssl_get_session(pc->connection);

	if (ssl_session == NULL) {
		return;
	}

	peer = &urpd->conf->peers[urpd->current];

	old_ssl_session = peer->ssl_session;
	peer->ssl_session = ssl_session;


	if (old_ssl_session) {

		ngx_ssl_free_session(old_ssl_session);
	}
}

#endif
