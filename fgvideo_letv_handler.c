/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include "fgvideo_common_handler.h"
#include "fgvideo_letv_handler.h"

static ngx_int_t letv_handler(ngx_http_request_t *r, ngx_str_t * \
		file_name, ngx_open_file_info_t *of, ngx_chain_t **out);

ngx_int_t
fgvideo_letv_ts_handler(ngx_http_request_t *r)
{
	return fgvideo_common_handler(r, letv_handler);
}

ngx_int_t
fgvideo_letv_letv_handler(ngx_http_request_t *r)
{
	return fgvideo_common_handler(r, letv_handler);
}

static ngx_int_t
letv_handler(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, ngx_chain_t **out)
{
	ngx_str_t	value;
	off_t		start, end;

	start = 0;
	end = of->size;

	if(r->args.len == 0){
		goto done;
	}

#define LETV_RSTART	"rstart"
	if(ngx_http_arg(r, (u_char *)LETV_RSTART, sizeof(LETV_RSTART) - 1, &value \
				) == NGX_OK){
		start = ngx_atoof(value.data, value.len);
		if(start == NGX_ERROR || start >= of->size){
			return NGX_HTTP_BAD_REQUEST;
		}
	}

#define LETV_REND "rend"
	if(ngx_http_arg(r, (u_char *)LETV_REND, sizeof(LETV_REND) - 1, &value) \
			== NGX_OK){
		end = ngx_atoof(value.data, value.len);

		if(end == NGX_ERROR || end >= of->size){
			return NGX_HTTP_BAD_REQUEST;
		}
	}

	if(start >= end){
		return NGX_HTTP_BAD_REQUEST;
	}

done:
	if(fgvideo_range_response(r, file_name, of, start, (end - start), out) \
			!= NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;

	return NGX_OK;
}
