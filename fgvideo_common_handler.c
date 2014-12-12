/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include "fgvideo_common_handler.h"

ngx_int_t
fgvideo_common_handler(ngx_http_request_t *r, fgvideo_handler fun){
    u_char                    *last;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_str_t                  path;
    ngx_log_t                 *log;
    ngx_chain_t                *out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

	if(fun(r, &path, &of, &out) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}

	return ngx_http_output_filter(r, out);
}

ngx_int_t
fgvideo_range_response(ngx_http_request_t *r, ngx_str_t *file_name, \
		ngx_open_file_info_t *of, off_t start, off_t len, \
		ngx_chain_t **out){

	ngx_buf_t		*b;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len;
	r->headers_out.last_modified_time = of->mtime;

	if((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if((b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t))) == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	r->allow_ranges = 1;

	b->file_pos = start;
	b->file_last = start + len;
	b->in_file = (b->file_last == 0) ? 0: 1;
	b->last_buf = (r == r->main) ? 1: 0;
	b->last_in_chain = 1;

	b->file->fd = of->fd;
	b->file->name = *file_name;
	b->file->log = r->connection->log;
	b->file->directio = of->is_directio;

	if((*out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t))) == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	(*out)->buf = b;
	(*out)->next = NULL;
	
	return NGX_OK;
}
