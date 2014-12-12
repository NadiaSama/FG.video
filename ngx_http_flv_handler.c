/*
 * Copyright (C) NadiaF0rever
 * Copyright (C) Beijing Datafrog Technology Co., Ltd.
 */

#include <sys/mman.h>
#include <stdio.h>

#include "ngx_http_flv_handler.h"

#define FLV_UI32(x) (unsigned int)(((x[0]) << 24) + ((x[1]) << 16) + ((x[2]) << 8) + (x[3]))
#define FLV_UI24(x) (unsigned int)(((x[0]) << 16) + ((x[1]) << 8) + (x[2]))
#define FLV_UI16(x) (unsigned int)(((x[0]) << 8) + (x[1]))
#define FLV_UI8(x) (unsigned int)((x))

#define FLV_NORMAL_FILE 	2
#define FLV_FORMAT_BAD		3

#define FLVTIME_KEYFRAMES_SYMBOL		"keyframes"
#define FLVTIME_FILEPOSITIONS_SYMBOL	"filepositions"
#define FLVTIME_TIMES_SYMBOL			"times"
#define FLVTIME_STARTARG_SYMBOL		"start"
#define FLVTIME_ENDARG_SYMBOL			"end"
#define FLVPOS_START_SYMBOL	"start"
#define FLVPOS_END_SYMBOL		"end"

/*
 * static u_char ngx_flv_sina_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";
 */

typedef struct{
	u_char signature[3];
	u_char version;
	u_char flags;
	u_char header_size[4];
}flv_header_t;

typedef struct{
	u_char type;
	u_char data_size[3];
	u_char time_stamp[3];
	u_char time_stampex;
	u_char stream_id[3];
}flv_tag_t;

typedef struct{
	off_t	offset;
	size_t	data_len;
}flv_taginfo_t;

typedef struct{
	ngx_file_t	file;
	off_t		end;
	void		*data;
	size_t		data_len;
	off_t		content_length;
	ngx_http_request_t	*r; 
	ngx_chain_t *tmp_out;
	ngx_chain_t out[3];
	flv_taginfo_t tags[3];
}flv_info_t;

typedef ngx_int_t (*flv_process_handler)(flv_info_t *flv_info);

static ngx_int_t ngx_http_flv_handler(ngx_http_request_t *r, flv_process_handler flv_process);
static ngx_int_t flv_info_init(ngx_http_request_t *r, ngx_open_file_info_t *flv, ngx_str_t *file_name, flv_info_t *flv_info);
static void flv_info_free(flv_info_t *flv_info);
static ngx_int_t flv_time_process(flv_info_t *flv_info);
static ngx_int_t flv_pos_process(flv_info_t *flv_info);

static ngx_buf_t *flv_build_buf_from_pos(flv_info_t *flv_info, off_t start, off_t end);
static void flv_append_buf(flv_info_t *flv_info, ngx_buf_t *buf);
static u_char *flv_strstr(const u_char *src, size_t src_len, const u_char *key, size_t key_len);
static double flv_number(const u_char *str);

static off_t flv_youku_getoffset_from_time(flv_info_t *flv_info, double start_time, double end_time, off_t *beg, off_t *end);
static ngx_int_t flv_youku_findless_val(ngx_array_t *array, double val);

static double
flv_number(const u_char *data){
	double ret;	
	u_char *tmp = (u_char *)&ret;

	tmp[0] = data[7];
	tmp[1] = data[6];
	tmp[2] = data[5];
	tmp[3] = data[4];
	tmp[4] = data[3];
	tmp[5] = data[2];
	tmp[6] = data[1];
	tmp[7] = data[0];

	return ret;

}
static u_char *
flv_strstr(const u_char *data, size_t data_len, const u_char *symbol, size_t symbol_len){
	size_t i, j, t;
//	u_char *ret;
	for(i = 0; i < data_len; i++){
		for(j = 0, t = i; j < symbol_len; j++, t++){
			if(symbol[j] != data[t]) break;
		}

		if(j == symbol_len) return (u_char *)(data + i);
	}

	return NULL;
}

static void
flv_append_buf(flv_info_t *flv_info, ngx_buf_t *buf){
	if(flv_info->tmp_out == NULL){
		flv_info->tmp_out = flv_info->out;
	}else{
		flv_info->tmp_out->next = flv_info->tmp_out + 1;
		flv_info->tmp_out += 1;
	}
	flv_info->tmp_out->buf = buf;
	flv_info->tmp_out->next = NULL;
	
	flv_info->content_length += ngx_buf_size(buf);
}

static ngx_buf_t *
flv_build_buf_from_pos(flv_info_t *flv_info, off_t start, off_t end){
	ngx_buf_t	*ret;
	ngx_pool_t	*pool = flv_info->r->pool;
	ngx_file_t *file = &flv_info->file;
	if(((ret = ngx_pcalloc(pool, sizeof(ngx_buf_t))) == NULL) || \
			(ret->file = ngx_palloc(pool, sizeof(ngx_file_t))) == NULL){
		return NULL;
	}

	ret->file_pos = start;
	ret->file_last = end;
	ret->in_file = end == 0 ? 0: 1;
	ret->file->fd = file->fd;
	ret->file->name = file->name;
	ret->file->directio = file->directio;
	ret->file->log = file->log;

	return ret;
}

static ngx_int_t
flv_youku_findless_val(ngx_array_t *array, double val){
	double t;
	double *data = (double *)array->elts;
	size_t beg = 0, end = array->nelts - 1, middle;

	while(beg <= end){
		middle = (beg + end) >> 1;
		t = data[middle];
		if(t > val){
			end = middle - 1;
		}else{
			beg = middle + 1;
		}
	}

	return end;
}

static off_t
flv_youku_getoffset_from_time(flv_info_t *flv_info, double start, double end, off_t *beg_pos, off_t *end_pos){
	u_char *metadata = (u_char *)flv_info->data + flv_info->tags[0].offset, *tmp;
	size_t	metadata_len = flv_info->tags[0].data_len;
	uint32_t	str_len;
	ngx_array_t	*times, *filepositions, *tmp_array;	
	uint32_t	array_len;
	double	*elem;
	ngx_int_t	index, i;

#if NGX_DEBUG
	ngx_log_t	*log = flv_info->r->connection->log;
#endif

	tmp = flv_strstr(metadata, metadata_len, (u_char *)FLVTIME_KEYFRAMES_SYMBOL, sizeof(FLVTIME_KEYFRAMES_SYMBOL) - 1);
	if(tmp == NULL) return FLV_FORMAT_BAD;

	tmp += sizeof(FLVTIME_KEYFRAMES_SYMBOL);
	str_len = FLV_UI16(tmp);/* str_len is the len of the field after keyframes field*/
	tmp += 2; 

	//tmp minght point to filepostions or times so ..
	if(str_len == sizeof(FLVTIME_FILEPOSITIONS_SYMBOL) - 1){
		tmp += sizeof(FLVTIME_FILEPOSITIONS_SYMBOL);
	}else if(str_len == sizeof(FLVTIME_TIMES_SYMBOL) - 1){
		tmp += sizeof(FLVTIME_TIMES_SYMBOL);
	}else{
		return FLV_FORMAT_BAD;
	}

	array_len = FLV_UI32(tmp);
	tmp += 4;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0, "%V array_len=%d", &flv_info->file.name, array_len);

	if((times = ngx_array_create(flv_info->r->pool, array_len, sizeof(double))) == NULL || 
			(filepositions = ngx_array_create(flv_info->r->pool, array_len, sizeof(double))) == NULL){
		return NGX_ERROR;
	}
	
	tmp_array = (str_len == sizeof(FLVTIME_TIMES_SYMBOL) - 1) ? times: filepositions;
	for(i = 0; i < array_len; i++){
		tmp++;
		elem = ngx_array_push(tmp_array);
		*elem = flv_number(tmp);
		tmp += 8;
	}

	str_len = FLV_UI16(tmp);
	tmp += 2;
	if(str_len == sizeof(FLVTIME_TIMES_SYMBOL) - 1){
		tmp_array = times;
		tmp += sizeof(FLVTIME_TIMES_SYMBOL);
	}else if(str_len == sizeof(FLVTIME_FILEPOSITIONS_SYMBOL) - 1){
		tmp_array = filepositions;
		tmp += sizeof(FLVTIME_FILEPOSITIONS_SYMBOL);
	}else{
		return FLV_FORMAT_BAD;
	}
	
	tmp += 4; 
	for(i = 0; i < array_len; i++){
		tmp++;
		elem = ngx_array_push(tmp_array);
		*elem = flv_number(tmp);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, "%V times[%d]=%f", &flv_info->file.name, i, *elem);
		tmp += 8;
	}

	if(start != 0){
		if((index = flv_youku_findless_val(times, start)) < 0) return NGX_HTTP_BAD_REQUEST;

		*beg_pos = (off_t)*((double *)filepositions->elts + index);
		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0, "%V start=%f index=%d beg_pos=%l", &flv_info->file.name, start, index, *beg_pos);
	}

	if(end != 0){
		if((index = flv_youku_findless_val(times, end)) < 0) return NGX_HTTP_BAD_REQUEST;

		*end_pos = (off_t)*((double *)filepositions->elts + index);
		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0, "%V end=%f index=%d end_pos=%l", &flv_info->file.name, end, index, *end_pos);

	}

	return NGX_OK;
}

static ngx_int_t
flv_time_process(flv_info_t *flv_info){
	off_t		start_pos, end_pos;
	ngx_str_t	value;
	ngx_buf_t	*b;
	ngx_int_t	rc, tmp;
	double		start_time, end_time;

#if NGX_DEBUG
	ngx_log_t	*log = flv_info->r->connection->log;
#endif

	start_pos = 0;
	end_pos = flv_info->end;
	start_time = 0;
	end_time = 0;

	if(flv_info->r->args.len){
		/*
		 * the method used to get start, end time is accoring to ngx_http_mp4_module.
		 */
		if(ngx_http_arg(flv_info->r, (u_char *)FLVTIME_STARTARG_SYMBOL, sizeof(FLVTIME_STARTARG_SYMBOL) - 1, &value) == NGX_OK){
			ngx_set_errno(0);
			start_time = strtod((char *)value.data, NULL);
			tmp = (int)start_time;
			if(errno != 0 || tmp < 0){
				start_time = 0;
			}
		}

		if(ngx_http_arg(flv_info->r, (u_char *)FLVTIME_ENDARG_SYMBOL, sizeof(FLVTIME_ENDARG_SYMBOL) - 1, &value) == NGX_OK){
			ngx_set_errno(0);
			end_time = strtod((char *)value.data, NULL);
			tmp = (int)end_time;

			if(tmp < 0 || errno != 0){
				end_time = 0;
			}
		}
	}

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, "%V start=%f end=%f", &flv_info->file.name, start_time, end_time);

	if(end_time != 0 && end_time <= start_time){
		return NGX_HTTP_BAD_REQUEST;
	}

	if(start_time != 0 || end_time != 0){
		rc = flv_youku_getoffset_from_time(flv_info, start_time, end_time, &start_pos, &end_pos);

		if(start_pos >= end_pos) return NGX_HTTP_BAD_REQUEST;
		if(rc != NGX_OK) return rc;

		if((b = flv_build_buf_from_pos(flv_info, 0, flv_info->tags[2].offset + flv_info->tags[2].data_len + 15)) \
				== NULL){ /* 15 = 11(sizeof(flv_tag_t)) + 4 */
			return NGX_ERROR;
		}
		flv_append_buf(flv_info, b);
	}

	if((b = flv_build_buf_from_pos(flv_info, start_pos, end_pos)) == NULL){
		return NGX_ERROR;
	}
	
	b->in_file = b->file_last ? 1: 0;
	b->last_buf = (flv_info->r == flv_info->r->main) ? 1: 0;
	b->last_in_chain = 1;
	flv_append_buf(flv_info, b);
	return NGX_OK;
}

static ngx_int_t
flv_pos_process(flv_info_t *flv_info){
	int		start_pos, end_pos, file_size; /* the flv size will not bigger than 1G, so we use int */
	ngx_str_t	value;
	ngx_buf_t	*b;
	flv_taginfo_t *tags = flv_info->tags;
#if NGX_DEBUG
	ngx_log_t	*log = flv_info->r->connection->log;
#endif

	start_pos = 0;
	file_size = (int)flv_info->end;
	end_pos = file_size;

	if(flv_info->r->args.len){
		if(ngx_http_arg(flv_info->r, (u_char *)FLVPOS_START_SYMBOL, sizeof(FLVPOS_START_SYMBOL) - 1, &value) == NGX_OK){
			start_pos = ngx_atoi(value.data, value.len);
			if(start_pos == NGX_ERROR){
				start_pos = 0;
			}
		}
		if(ngx_http_arg(flv_info->r, (u_char *)FLVPOS_END_SYMBOL, sizeof(FLVPOS_END_SYMBOL) - 1, &value) == NGX_OK){
			end_pos = ngx_atoi(value.data, value.len);
			if(end_pos == NGX_ERROR){
				end_pos = file_size;
			}
		}
	}

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0, "%V %V start_pos=%d, end_pos=%d", \
			&flv_info->file.name, &flv_info->r->args, start_pos, end_pos);

	if(start_pos == file_size || end_pos > file_size || start_pos >= end_pos){
		return NGX_HTTP_BAD_REQUEST;
	}

	if(start_pos != 0){
		b = flv_build_buf_from_pos(flv_info, 0, tags[0].offset);
		if(b == NULL){
			return NGX_ERROR;
		}
		flv_append_buf(flv_info, b);

		b = flv_build_buf_from_pos(flv_info, tags[1].offset, tags[2].offset + \
				tags[2].data_len + 15);/* 15 = sizeof(flv_tag_t) + 4 */
		if(b == NULL){
			return NGX_ERROR;
		}
		flv_append_buf(flv_info, b);
	}

	if((b = flv_build_buf_from_pos(flv_info, start_pos, end_pos)) == NULL){
		return NGX_ERROR;
	}
	b->in_file = 1;
	b->last_in_chain = 1;
	b->last_buf = (flv_info->r == flv_info->r->main) ? 1: 0;
	flv_append_buf(flv_info, b);

	return NGX_OK;
}

static ngx_int_t
flv_info_init(ngx_http_request_t *r, ngx_open_file_info_t *flv, ngx_str_t *file_name, flv_info_t *flv_info){	
	flv_header_t		*header;
	flv_tag_t			*tag;
	size_t				data_len, tmp_pos = 0, tmp_len;
	u_char				*data;
	ngx_int_t			i;
	ngx_fd_t			fd;
#if NGX_DEBUG
	ngx_log_t			*log = r->connection->log;
#endif

	flv_info->r	= r;
	flv_info->file.fd = flv->fd;
	flv_info->file.directio = flv->is_directio;
	flv_info->file.name = *file_name;
	flv_info->file.log = r->connection->log;
	flv_info->end = flv->size;

	fd = flv_info->file.fd;
	data_len = ngx_pagesize;
	if((data = (u_char *)mmap(NULL, data_len, PROT_READ, MAP_SHARED, fd, 0)) == NULL) return NGX_ERROR;
	flv_info->data_len = data_len;
	flv_info->data = data;

	header = (flv_header_t *)data;
	if(data[0] != 'F' || data[1] != 'L' || data[2] != 'V'){
		return FLV_NORMAL_FILE;
	}

	tmp_pos += FLV_UI32(header->header_size) + 4;
	if(tmp_pos + sizeof(flv_tag_t) > data_len){
		if(munmap(data, data_len) != 0){
			return NGX_ERROR;
		}
		data_len = ((tmp_pos + sizeof(flv_tag_t)) / ngx_pagesize + 1) * ngx_pagesize;
		
		if((data = (u_char *)mmap(NULL, data_len, PROT_READ, MAP_SHARED, fd, 0)) == NULL) return NGX_ERROR;
		flv_info->data_len = data_len;
		flv_info->data = data;
	}

	for(i = 0; i < 3; i++){
		tag = (flv_tag_t *)(data + tmp_pos);
		
		flv_info->tags[i].offset = tmp_pos;
		tmp_len = FLV_UI24(tag->data_size);
		flv_info->tags[i].data_len = tmp_len;

		tmp_pos += sizeof(flv_tag_t) + tmp_len + 4;
		ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0, "%V tag[%d].offset = %l tag[%d].len = %ud", \
			&flv_info->file.name, i, flv_info->tags[i].offset, i, flv_info->tags[i].data_len);

		if(tmp_pos + sizeof(flv_tag_t) > data_len){
			if(munmap(data, data_len) != 0){
				return NGX_ERROR;
			}
			data_len = ((tmp_pos + sizeof(flv_tag_t)) / ngx_pagesize + 1) * ngx_pagesize;
			
			if((data = (u_char *)mmap(NULL, data_len, PROT_READ, MAP_SHARED, fd, 0)) == NULL) return NGX_ERROR;
			flv_info->data_len = data_len;
			flv_info->data = data;
		}
	}
	return NGX_OK;
}

static void
flv_info_free(flv_info_t *flv_info){
	munmap(flv_info->data, flv_info->data_len);
}

static ngx_int_t
ngx_http_flv_handler(ngx_http_request_t *r, flv_process_handler flv_process){
    u_char                    *last;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_str_t                  path;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                *out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
	flv_info_t					flv_info;

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

	ngx_memzero(&flv_info, sizeof(flv_info_t));
	rc = flv_info_init(r, &of, &path, &flv_info);
	
	if(rc == NGX_ERROR){
		ngx_log_error(NGX_LOG_ERR, log, 0, "mmap/unmap error %d", ngx_errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}else if(rc == FLV_NORMAL_FILE){
		flv_info_free(&flv_info);
		if((out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t))) == NULL || \
				(b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL || \
				(b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t))) == NULL){
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		b->file_pos = 0;
		b->file_last = of.size;

		b->in_file = b->file_last ? 1: 0;
		b->last_buf = (r == r->main) ? 1: 0;
		b->last_in_chain = 1;
		b->file->fd = of.fd;
		b->file->name = path;
		b->file->log = log;
		b->file->directio = of.is_directio;

		out->buf = b;
		out->next = NULL;
		
		r->headers_out.content_length_n = of.size;
		goto done;
	}

	rc = flv_process(&flv_info);
	flv_info_free(&flv_info);
	switch(rc){
	case FLV_FORMAT_BAD: /*for flv_time_process failed get metadata */
		ngx_log_error(NGX_LOG_WARN, log, 0, "BAD_FLV_FORMAT %V", &flv_info.file.name);

	case NGX_ERROR: /*ngx_pcalloc error failed get memory*/
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	case NGX_HTTP_BAD_REQUEST:
		/*
		 * for flv_pos_process {(start_pos >= end_pos || start_pos = file_size || end_pos > file_size) == true}
		 *
		 * for flv_time_process fail get file position from flv metadata and, start end time. 
		 * or start_pos >= end_pos or start_time >= end_time
		 *
		 */
		return NGX_HTTP_BAD_REQUEST;

	case NGX_OK:
		r->headers_out.content_length_n = flv_info.content_length;
		break;

	default:
		ngx_log_error(NGX_LOG_ALERT, log, 0, "UNHANDLE RETURN VALUE %d", rc);
		exit(1);
	}

	out = flv_info.out;
done:
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = of.mtime;
	if(ngx_http_set_etag(r) != NGX_OK || ngx_http_set_content_type(r) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}
	return ngx_http_output_filter(r, out);
}

ngx_int_t
ngx_http_flv_time_handler(ngx_http_request_t *r){
	return ngx_http_flv_handler(r, flv_time_process);
}

ngx_int_t
ngx_http_flv_pos_handler(ngx_http_request_t *r){
	return ngx_http_flv_handler(r, flv_pos_process);
}
