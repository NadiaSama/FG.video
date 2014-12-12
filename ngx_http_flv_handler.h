#ifndef XFG8_0_NGX_HTTP_FLV_HANDLER_H
#define XFG8_0_NGX_HTTP_FLV_HANDLER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define YOUKU_SYMBOL	"type=youku" 

/*
 * used to handle flv get request for youku jstv. 
 * The request args has formart ?[start=${time}(time is double type)]&[end=${time}]
 */
ngx_int_t
ngx_http_flv_time_handler(ngx_http_request_t *r);


/*
 * used to handle  flv get request for sina, mangguo...
 * The request args has formast ?start=${POS}[&end=${POS}]
 */
ngx_int_t
ngx_http_flv_pos_handler(ngx_http_request_t *r);
#endif
