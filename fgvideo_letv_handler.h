#ifndef FGVIDEO_LETV_HANDLER_H
#define FGVIDEO_LETV_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#define letv_request(r) ngx_strnstr((u_char *)(r)->args.data, \
		"type=letv", (r)->args.len) != NULL

ngx_int_t fgvideo_letv_ts_handler(ngx_http_request_t *r);
ngx_int_t fgvideo_letv_letv_handler(ngx_http_request_t *r);
#endif
