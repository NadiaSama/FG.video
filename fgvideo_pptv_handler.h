#ifndef FGVIDEO_EEIWANT_PPTV_HANDLER_H
#define FGVIDEO_EEIWANT_PPTV_HANDLER_H

#define pptv_request(r) (ngx_strnstr((u_char *)(r)->args.data, \
			"type=pptv", (r)->args.len) != NULL)

ngx_int_t fgvideo_pptv_handler(ngx_http_request_t *r);

#endif
