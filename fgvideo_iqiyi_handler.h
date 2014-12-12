#ifndef FGVIDEO_IQIYI_HANDLER_H
#define FGVIDEO_IQIYI_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#define iqiyi_request(r) ngx_strnstr((u_char *)(r)->args.data, \
		"type=iqiyi", (r)->args.len) != NULL

ngx_int_t fgvideo_iqiyi_handler(ngx_http_request_t *r);
#endif
