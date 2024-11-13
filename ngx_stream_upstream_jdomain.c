#include "ngx_upstream_jdomain.h"
#include <ngx_stream.h>

extern ngx_module_t ngx_stream_upstream_jdomain_module;

static ngx_int_t
ngx_stream_upstream_jdomain_init_peer(ngx_stream_session_t *s,
	ngx_stream_upstream_srv_conf_t *us)
{
	ngx_upstream_jdomain_srv_conf_t	*urcf;

	urcf = ngx_stream_conf_upstream_srv_conf(us, ngx_stream_upstream_jdomain_module);
	return ngx_upstream_jdomain_init_peer(s->connection->pool, &s->upstream->peer, urcf);
}

static ngx_int_t
ngx_stream_upstream_jdomain_init(ngx_conf_t *cf, ngx_stream_upstream_srv_conf_t *us)
{
	ngx_upstream_jdomain_main_conf_t	*jmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_jdomain_module);
	ngx_upstream_jdomain_srv_conf_t	*urcf;

	us->peer.init = ngx_stream_upstream_jdomain_init_peer;

	urcf = ngx_stream_conf_upstream_srv_conf(us, ngx_stream_upstream_jdomain_module);
	return ngx_upstream_jdomain_init(cf, jmcf, urcf);
}

static char *
ngx_stream_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_stream_upstream_srv_conf_t  *uscf;
	ngx_upstream_jdomain_srv_conf_t *urcf = conf;

#if (nginx_version) >= 1007003
	ngx_stream_upstream_server_t	*us;
#endif

	uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

	/*Just For Padding,upstream{} need it*/
	if(uscf->servers == NULL) {
		uscf->servers = ngx_array_create(cf->pool, 1,
	                                     sizeof(ngx_stream_upstream_server_t));
		if(uscf->servers == NULL) {
			return NGX_CONF_ERROR;
		}
	}

#if (nginx_version) >= 1007003
	us = ngx_array_push(uscf->servers);
	if (us == NULL) {
		return NGX_CONF_ERROR;
	}
	ngx_memzero(us, sizeof(*us));
#endif

	uscf->peer.init_upstream = ngx_stream_upstream_jdomain_init;

	return ngx_upstream_jdomain(cf, cmd, urcf);
}

static char *
ngx_stream_upstream_jdomain_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	return ngx_upstream_jdomain_resolver(cf, cmd, conf);
}

static ngx_command_t  ngx_stream_upstream_jdomain_commands[] = {
	{ngx_string("jdomain"),
	 NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
	 ngx_stream_upstream_jdomain,
	 NGX_STREAM_SRV_CONF_OFFSET,
	 0,
	 NULL },

	{ngx_string("jdomain_resolver"),
	 NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
	 ngx_stream_upstream_jdomain_resolver,
	 NGX_STREAM_SRV_CONF_OFFSET,
	 0,
	 NULL },

	{ngx_string("jdomain_resolver_timeout"),
	 NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
	 ngx_conf_set_msec_slot,
	 NGX_STREAM_SRV_CONF_OFFSET,
	 offsetof(ngx_upstream_jdomain_srv_conf_t, resolver_timeout),
	 NULL },

	 ngx_null_command
};

static void *
ngx_stream_upstream_jdomain_create_main_conf(ngx_conf_t *cf)
{
	ngx_upstream_jdomain_main_conf_t	*jmcf;

	jmcf = ngx_pcalloc(cf->pool, sizeof(*jmcf));
	if (jmcf == NULL) {
		return NULL;
	}

	return jmcf;
}

static void *
ngx_stream_upstream_jdomain_create_conf(ngx_conf_t *cf)
{
	ngx_upstream_jdomain_srv_conf_t	*conf;

	conf = ngx_pcalloc(cf->pool,
			sizeof(ngx_upstream_jdomain_srv_conf_t));
	if (conf == NULL) {
		return NULL;
	}
	conf->resolver_timeout = NGX_CONF_UNSET_MSEC;

	return conf;
}

static ngx_int_t
ngx_stream_upstream_jdomain_init_process(ngx_cycle_t *cycle)
{
	ngx_upstream_jdomain_main_conf_t	*jmcf;

	jmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_upstream_jdomain_module);
	return ngx_upstream_jdomain_init_process(cycle, jmcf);
}

static ngx_stream_module_t  ngx_stream_upstream_jdomain_module_ctx = {
	NULL,								/* preconfiguration */
	NULL,								/* postconfiguration */

	ngx_stream_upstream_jdomain_create_main_conf,	/* create main configuration */
	NULL,								/* init main configuration */

	ngx_stream_upstream_jdomain_create_conf,	/* create server configuration */
	NULL								/* merge server configuration */
};

ngx_module_t  ngx_stream_upstream_jdomain_module = {
	NGX_MODULE_V1,
	&ngx_stream_upstream_jdomain_module_ctx,	/* module context */
	ngx_stream_upstream_jdomain_commands,	/* module directives */
	NGX_STREAM_MODULE,			/* module type */
	NULL,						/* init master */
	NULL,						/* init module */
	ngx_stream_upstream_jdomain_init_process,	/* init process */
	NULL,						/* init thread */
	NULL,						/* exit thread */
	NULL,						/* exit process */
	NULL,						/* exit master */
	NGX_MODULE_V1_PADDING
};
