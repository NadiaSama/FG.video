/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include "fgvideo_common_handler.h"
#include "fgvideo_iqiyi_handler.h"

#include "ngx_http_flv_handler.h"

#define iqiyirange_request(r) ngx_strnstr((u_char *)(r)->args.data, \
		"range=", (r)->args.len) != NULL

static ngx_int_t iqiyi_handler(ngx_http_request_t *r, ngx_str_t * \
		file_name, ngx_open_file_info_t *of, ngx_chain_t **out);

ngx_int_t
fgvideo_iqiyi_handler(ngx_http_request_t *r){
	if(iqiyirange_request(r)){
		return fgvideo_common_handler(r, iqiyi_handler);
	}
	
	return ngx_http_flv_pos_handler(r);
}


static ngx_int_t
iqiyi_handler(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, ngx_chain_t **out){
	u_char 			*t, *beg, *end;
	ngx_str_t		value;
	off_t			start, len;
	
	start = 0;
	len = of->size;

	if(r->args.len == 0){
		goto done;
	}

#define IQIYI_RANGE		"range"
	if(ngx_http_arg(r, (u_char *)IQIYI_RANGE, sizeof(IQIYI_RANGE) \
				- 1, &value) != NGX_OK){
		goto done;
	}

	beg = (u_char *)value.data;
	end = beg + value.len;

	t = ngx_strlchr(beg, end, '-');
	if(t == NULL){
		goto done;
	}

	start = ngx_atoof(beg, t - beg);
	if(start == NGX_ERROR || start >= of->size){
		start = 0;
	}

	len = ngx_atoof(t + 1, end - t - 1);
	if(len < start || len >= of->size){
		len = of->size;
	}
	len -= (start - 1);

done:
	if(fgvideo_range_response(r, file_name, of, start, len, out) \
			!= NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;

	return NGX_OK;
}
