#ifndef FGVIDEO_EEIWANT_YOUKU_HANDLER_H
#define FGVIDEO_EEIWANT_YOUKU_HANDLER_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#define youku_request(r) ngx_strnstr((u_char *)(r)->args.data, \
		"type=youku", (r)->args.len) != NULL

ngx_int_t fgvideo_youku_flv_handler(ngx_http_request_t *r);
ngx_int_t fgvideo_youku_mp4_handler(ngx_http_request_t *r);
#endif
