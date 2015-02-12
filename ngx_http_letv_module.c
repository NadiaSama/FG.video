/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include "fgvideo_letv_handler.h"

static char *ngx_http_letv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t 	ngx_http_letv_commands[] = {
	{
		ngx_string("letv"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_letv,
		0,
		0,
		NULL
	},

	ngx_null_command
};

static ngx_http_module_t	ngx_http_letv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t 	ngx_http_letv_module = {
	NGX_MODULE_V1,
	&ngx_http_letv_module_ctx,
	ngx_http_letv_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};


static char *
ngx_http_letv(ngx_conf_t *cf, ngx_command_t *cmd, void *arg){
	ngx_http_core_loc_conf_t *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = fgvideo_letv_letv_handler;

	return NGX_CONF_OK;
}
