/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include "fgvideo_common_handler.h"
#include "fgvideo_pptv_handler.h"

static ngx_int_t pptv_handler(ngx_http_request_t *r, ngx_str_t * \
		file_name, ngx_open_file_info_t *of, ngx_chain_t **out);

ngx_int_t
fgvideo_pptv_handler(ngx_http_request_t *r){
	return fgvideo_common_handler(r, pptv_handler);
}

static ngx_int_t
pptv_handler(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, ngx_chain_t **out){
	off_t		start, end;
	ngx_str_t	value;

	start = 0;
	end = of->size;

	if(r->args.len == 0){
		goto done;
	}

#define START 	"start"
	if(ngx_http_arg(r, (u_char *)START, sizeof(START) - 1, &value \
				) == NGX_OK){
		start = ngx_atoof((u_char *)value.data, value.len);

		if(start == NGX_ERROR || start > of->size){
			start = 0;
		}
	}
#define END		"end"
	if(ngx_http_arg(r, (u_char *)END, sizeof(END) - 1, &value \
				) == NGX_OK){
		end = ngx_atoof((u_char *)value.data, value.len);

		if(end == NGX_ERROR || end > of->size || end == 0 || end < start){
			end = of->size;
		}else{
			end += 1;
		}
	}

done:

	return fgvideo_range_response(r, file_name, of, start, \
			end - start, out);
}
