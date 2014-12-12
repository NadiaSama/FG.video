/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include "fgvideo_common_handler.h"
#include "fgvideo_youku_handler.h"
#include "ngx_http_flv_handler.h"
#include "ngx_http_mp4_handler.h"

#define youkuns_request(r) ngx_strnstr((u_char *)(r)->args.data, \
		"ns=", (r)->args.len) != NULL

static ngx_int_t youkuns_handler(ngx_http_request_t *r, ngx_str_t \
		*file_name, ngx_open_file_info_t *of, ngx_chain_t **out);

ngx_int_t
fgvideo_youku_flv_handler(ngx_http_request_t *r){
	if(youkuns_request(r)){
		return fgvideo_common_handler(r, youkuns_handler);
	}

	return ngx_http_flv_time_handler(r);
}

static ngx_int_t 
youkuns_handler(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, ngx_chain_t **out){
	ngx_str_t	value;
	off_t		start, len;
	int			t;
	u_char		*tmp;

	start = 0;
#define YOUKUNS_DEFAULT_LEN	20000
	len = YOUKUNS_DEFAULT_LEN;
	if(r->args.len == 0){
		goto done;
	}
	if(ngx_http_arg(r, (u_char *)"ns", 2, &value) != NGX_OK){
		goto done;
	}
	tmp = ngx_strlchr((u_char *)value.data, (u_char *)value.data \
			+ value.len, '_');

	if(tmp != NULL){
		start = ngx_atoof(value.data, tmp - value.data);
		if(start == NGX_ERROR || start > of->size){
			start = 0;
		}

		t = ngx_atoi(tmp + 1, 1);
		if(t == 1 || t == NGX_ERROR){
			start = 0;
		}else{
			tmp += 2;
			len = ngx_atoof(tmp, (value.data + value.len) - tmp);
			if(len == NGX_ERROR || len > of->size){
				len = YOUKUNS_DEFAULT_LEN;
			}
		}

		if(start + len > of->size){
			len = of->size - start;
		}
	}

done:
	return fgvideo_range_response(r, file_name, of, start, len, out);
}

ngx_int_t
fgvideo_youku_mp4_handler(ngx_http_request_t *r){
	if(youkuns_request(r)){
		return fgvideo_common_handler(r, youkuns_handler);
	}

	return ngx_http_mp4_handler(r);
}
