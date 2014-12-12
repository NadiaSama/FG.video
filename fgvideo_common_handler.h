#ifndef NGX_HTTP_EEIWANT_HANDLER_INTERNAL_H
#define NGX_HTTP_EEIWANT_HANDLER_INTERNAL_H

#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_config.h>

typedef ngx_int_t (* fgvideo_handler)(ngx_http_request_t *r, \
		ngx_str_t *name, ngx_open_file_info_t *of, ngx_chain_t **out);

ngx_int_t
fgvideo_common_handler(ngx_http_request_t *r, fgvideo_handler fun);

ngx_int_t
fgvideo_range_response(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, off_t start, off_t len, \
		ngx_chain_t **out);

#endif
