#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "logger.h"
#include "fdfs_client.h"
#include "shared_func.h"
#include "client_global.h"
#include "fdfs_http_shared.h"
#include "fdfs_global.h"

#if __GNUC__ >= 3
# define INLINE                     static inline
#else
# define INLINE                     static
#endif

#define FDFS_CONFIG_FILE            "/etc/fdfs/client.conf"

TrackerServerGroup g_tracker_group;

/* common function */

INLINE bool hv_trackerserver(HV *server, TrackerServerInfo *server_info){

    SV *ip_addr = NULL;
    SV *port    = NULL;
    SV *sock    = NULL;

    int check_error = 0;
    
    if(hv_exists(server, "ip_addr", 7)){
        ip_addr =  *hv_fetch(server, "ip_addr", 7, 0);
    }else{
        check_error++;
    }
    if(hv_exists(server, "port", 4)){
        port    =  *hv_fetch(server, "port", 4, 0);
    }else{
        check_error++;
    }
    if(hv_exists(server, "sock", 4)){
        sock    =  *hv_fetch(server, "sock", 4, 0);
    }else{
        check_error++;
    }
    if(check_error == 0){
        snprintf(server_info->ip_addr,  sizeof(server_info->ip_addr), "%s", SvPV_nolen(ip_addr));
        server_info->port = SvIV(port);
        server_info->sock = SvIV(sock);
        return TRUE;
    }else{
        return FALSE;
    }    
}

INLINE void trackerserver_hv(TrackerServerInfo *server_info, HV *hv){
    SV **cur;
    cur = hv_store(hv, "ip_addr", 7, newSVpv(server_info->ip_addr,0), 0);
    cur = hv_store(hv, "port", 4, newSViv(server_info->port),0);
    cur = hv_store(hv, "sock", 4, newSViv(server_info->sock),0);
    cur = NULL;
}

INLINE int split_file_id(const char *file_id, char *group_name, char *file_name){
    char *p = NULL;
    char new_file_id[FDFS_GROUP_NAME_MAX_LEN+128];

    strcpy(new_file_id, file_id);
    p = strchr(new_file_id, FDFS_FILE_ID_SEPERATOR);
    if(p == NULL){
        return -1;
    }
    *p = '\0';
    strcpy(group_name, new_file_id);
    p++;
    strcpy(file_name, p);
    return 0;
}

static int load_config_files(){
    int result;
    result = fdfs_client_init(FDFS_CONFIG_FILE);
    return result;
}

HV *perl_tracker_do_query_storage(char *group_name, char *remote_filename, int cmd, HV *server){
    int result;
    TrackerServerInfo *trackserver = NULL;
    TrackerServerInfo storage_server;

    if(server == NULL){
        trackserver = tracker_get_connection();
    }else{
        if(hv_trackerserver(server, trackserver) != 0){
            return NULL;
        }
    }

    result = tracker_do_query_storage(trackserver, &storage_server, cmd,  group_name, remote_filename);
    if(result == 0){
        HV *hv = newHV();
        trackerserver_hv(&storage_server, hv);
        return hv;
    }else{
        return NULL;
    }
}

AV *perl_tracker_query_storage_list(char *group_name, char *remote_filename, HV *server){
    int result;
    int server_count;
    TrackerServerInfo *trackserver = NULL;
    TrackerServerInfo *pServer = NULL;
    TrackerServerInfo *pServerEnd;
    TrackerServerInfo storage_servers[FDFS_MAX_SERVERS_EACH_GROUP];

    if(server == NULL){
        trackserver = tracker_get_connection();
    }else{
        if(hv_trackerserver(server, trackserver) != 0){
            return NULL;
        }
    }

    result = tracker_query_storage_list(trackserver, storage_servers, FDFS_MAX_SERVERS_EACH_GROUP, &server_count, group_name, remote_filename);
    if(result == 0){
        AV *av = newAV();
        pServerEnd = storage_servers + server_count;
        for (pServer=storage_servers; pServer<pServerEnd; pServer++){
            HV *hv = newHV();
            trackerserver_hv(pServer, hv);
            av_push(av, newRV_noinc((SV *)hv));
        }
        return av;
    }else{
        return NULL;
    }
}

HV *perl_fdfs_storage_upload_file(char *local_filename, const char *group_name){
    int result;
    int store_path_index;
    char remote_filename[128];
    char remote_group[FDFS_GROUP_NAME_MAX_LEN + 1];
    TrackerServerInfo *trackserver = NULL;
    TrackerServerInfo storage_server;
    trackserver = tracker_get_connection();
    
    if(group_name == NULL){
        result = tracker_query_storage_store_without_group(trackserver, &storage_server, &store_path_index);
    }else{
        strcpy(remote_group, group_name);
        result = tracker_query_storage_store_with_group(trackserver, group_name, &storage_server, &store_path_index);
    }
    if(result != 0){
        return NULL;
    }
    result = storage_upload_by_filename(trackserver, &storage_server, store_path_index, local_filename, NULL, NULL, 0, remote_group, remote_filename);

    if(result != 0){
        return NULL;
    }
    HV *hv = newHV();
    SV **cur = NULL;
    cur = hv_store(hv, "group_name", 10, newSVpv(remote_group,0), 0);
    cur = hv_store(hv, "file_name",  9, newSVpv(remote_filename,0), 0);
    cur = NULL;
    return hv;
}

//Begin XS Code
MODULE = FastDFS::Client                PACKAGE = FastDFS::Client

BOOT:
    log_init();
    g_log_context.log_level = LOG_ERR;
    load_config_files();

SV *
fastdfs_client_version()
    CODE:
        char version[16];
        sprintf(version, "%d.%02d", g_fdfs_version.major, g_fdfs_version.minor);
        RETVAL = newSVpv(version,0);
    OUTPUT:
        RETVAL

bool
fastdfs_active_test(HV *server)
    CODE:
        TrackerServerInfo server_info;
        hv_trackerserver(server, &server_info);
        if(fdfs_active_test(&server_info) == 0){
            RETVAL = 1;
        }else{
            XSRETURN_UNDEF;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_connect_server(char *ip_addr, int port)
    CODE:
        TrackerServerInfo server_info; 
        snprintf(server_info.ip_addr, sizeof(server_info.ip_addr), "%s", ip_addr);
	server_info.port = port;
	server_info.sock = -1;
        if(tracker_connect_server(&server_info) == 0){
            HV *hv = newHV();
            trackerserver_hv(&server_info, hv);
            RETVAL = hv;
        }else{
            XSRETURN_UNDEF;
        }
    OUTPUT:
        RETVAL

void
fastdfs_disconnect_server(HV *server)
    CODE:
        TrackerServerInfo server_info;
        hv_trackerserver(server, &server_info);
        tracker_disconnect_server(&server_info);
        hv_undef(server);

HV *
fastdfs_tracker_get_connection()
    CODE:
        TrackerServerInfo *pTrackerServer = NULL;
        pTrackerServer = tracker_get_connection();
        if(pTrackerServer != NULL){
            HV *hv = newHV();
            trackerserver_hv(pTrackerServer, hv);
            RETVAL = hv;
        }else{
            XSRETURN_UNDEF;
        }
    OUTPUT:
        RETVAL

bool
fastdfs_tracker_make_all_connections()
    CODE:
        int result;
        result = tracker_get_all_connections();
        if(result == 0){
            RETVAL = 1;
        }else{
            XSRETURN_UNDEF;
        }
    OUTPUT:
        RETVAL

void
fastdfs_tracker_close_all_connections()
    CODE:
        tracker_close_all_connections();

HV *
fastdfs_tracker_list_groups(HV *server=NULL)
    CODE:
        TrackerServerInfo *trackserver = NULL;
        if(server == NULL){
            trackserver = tracker_get_connection();
        }else{
            if(hv_trackerserver(server, trackserver) != 0){
                XSRETURN_UNDEF;
            }
        }
        if(trackserver != NULL){

            HV *hv = newHV();

            FDFSGroupStat group_stats[FDFS_MAX_GROUPS];
            FDFSGroupStat *pGroupStat;
            FDFSGroupStat *pGroupEnd;

            FDFSStorageInfo storage_infos[FDFS_MAX_SERVERS_EACH_GROUP];
            FDFSStorageInfo *pStorage;
            FDFSStorageInfo *pStorageEnd;
            FDFSStorageStat *pStorageStat;

            int group_count;
            int storage_count;

            if(tracker_list_groups(trackserver, group_stats, FDFS_MAX_GROUPS, &group_count) != 0){
                XSRETURN_UNDEF;
            }

            pGroupEnd = group_stats + group_count;
            for(pGroupStat=group_stats; pGroupStat<pGroupEnd; pGroupStat++){
                HV *hv1 = newHV();
                SV **cur;
                cur = hv_store(hv1, "free_space",            10, newSViv(pGroupStat->free_mb),               0);
                cur = hv_store(hv1, "trunk_free_space",      16, newSViv(pGroupStat->trunk_free_mb),         0);
                cur = hv_store(hv1, "server_count",          12, newSViv(pGroupStat->count),                 0);
                cur = hv_store(hv1, "active_count",          12, newSViv(pGroupStat->active_count),          0);
                cur = hv_store(hv1, "storage_port",          12, newSViv(pGroupStat->storage_port),          0);
                cur = hv_store(hv1, "storage_http_port",     17, newSViv(pGroupStat->storage_http_port),     0);
                cur = hv_store(hv1, "store_path_count",      16, newSViv(pGroupStat->store_path_count),      0);
                cur = hv_store(hv1, "subdir_count_per_path", 21, newSViv(pGroupStat->subdir_count_per_path), 0);
                cur = hv_store(hv1, "current_write_server",  20, newSViv(pGroupStat->current_write_server),  0);
                cur = hv_store(hv1, "current_trunk_file_id", 21, newSViv(pGroupStat->current_trunk_file_id), 0);

                if(tracker_list_servers(trackserver, pGroupStat->group_name, NULL, storage_infos, FDFS_MAX_SERVERS_EACH_GROUP, &storage_count) != 0){
                    XSRETURN_UNDEF;
                }
                pStorageEnd = storage_infos + storage_count;
                for (pStorage=storage_infos; pStorage<pStorageEnd; pStorage++){
                    HV *storage = newHV();
                    cur = hv_store(storage, "join_time",   9,  newSViv(pStorage->join_time),     0);
                    cur = hv_store(storage, "up_time",     7,  newSViv(pStorage->up_time),       0);
                    cur = hv_store(storage, "http_domain", 11, newSVpv(pStorage->domain_name,0), 0);
                    cur = hv_store(storage, "version",     7,  newSVpv(pStorage->version,0),     0);
                    cur = hv_store(storage, "src_ip_addr", 11,  newSVpv(pStorage->src_ip_addr,0), 0);
                    cur = hv_store(storage, "if_trunk_server",  15, newSViv(pStorage->if_trunk_server), 0);
                    cur = hv_store(storage, "upload_priority",  15, newSViv(pStorage->upload_priority), 0);
                    cur = hv_store(storage, "store_path_count", 16, newSViv(pStorage->store_path_count), 0);
                    cur = hv_store(storage, "subdir_count_per_path", 21, newSViv(pStorage->subdir_count_per_path), 0);
                    cur = hv_store(storage, "storage_port", 12, newSViv(pStorage->storage_port), 0);
                    cur = hv_store(storage, "storage_http_port", 17, newSViv(pStorage->storage_http_port), 0);
                    cur = hv_store(storage, "current_write_path",18, newSViv(pStorage->current_write_path), 0);
                    cur = hv_store(storage, "status", 6, newSViv(pStorage->status), 0);
                    cur = hv_store(storage, "total_space", 11, newSViv(pStorage->total_mb), 0);
                    cur = hv_store(storage, "free_space", 10, newSViv(pStorage->free_mb), 0);
                    pStorageStat = &(pStorage->stat);
                    cur = hv_store(storage, "total_upload_count",18, newSViv(pStorageStat->total_upload_count), 0);
                    cur = hv_store(storage, "success_upload_count",20, newSViv(pStorageStat->success_upload_count), 0);
                    cur = hv_store(storage, "total_append_count",18, newSViv(pStorageStat->total_append_count), 0);
                    cur = hv_store(storage, "success_append_count",20, newSViv(pStorageStat->success_append_count), 0);
                    cur = hv_store(storage, "total_set_meta_count",20, newSViv(pStorageStat->total_set_meta_count), 0);
                    cur = hv_store(storage, "success_set_meta_count",22, newSViv(pStorageStat->success_set_meta_count), 0);
                    cur = hv_store(storage, "total_delete_count",18, newSViv(pStorageStat->total_delete_count), 0);
                    cur = hv_store(storage, "success_delete_count",20, newSViv(pStorageStat->success_delete_count), 0);
                    cur = hv_store(storage, "total_download_count",20, newSViv(pStorageStat->total_download_count), 0);
                    cur = hv_store(storage, "success_download_count",22, newSViv(pStorageStat->success_download_count), 0);
                    cur = hv_store(storage, "total_get_meta_count",20, newSViv(pStorageStat->total_get_meta_count), 0);
                    cur = hv_store(storage, "success_get_meta_count",22, newSViv(pStorageStat->success_get_meta_count), 0);
                    cur = hv_store(storage, "total_create_link_count",23, newSViv(pStorageStat->total_create_link_count), 0);
                    cur = hv_store(storage, "success_create_link_count",25, newSViv(pStorageStat->success_create_link_count), 0);
                    cur = hv_store(storage, "total_delete_link_count",23, newSViv(pStorageStat->total_delete_link_count), 0);
                    cur = hv_store(storage, "success_delete_link_count",25, newSViv(pStorageStat->success_delete_link_count), 0);
                    cur = hv_store(storage, "total_upload_bytes",18, newSViv(pStorageStat->total_upload_bytes), 0);
                    cur = hv_store(storage, "success_upload_bytes",20, newSViv(pStorageStat->success_upload_bytes), 0);
                    cur = hv_store(storage, "total_append_bytes",18, newSViv(pStorageStat->total_append_bytes), 0);
                    cur = hv_store(storage, "success_append_bytes",20, newSViv(pStorageStat->success_append_bytes), 0);
                    cur = hv_store(storage, "total_download_bytes",20, newSViv(pStorageStat->total_download_bytes), 0);
                    cur = hv_store(storage, "success_download_bytes",22, newSViv(pStorageStat->success_download_bytes), 0);
                    cur = hv_store(storage, "total_sync_in_bytes",19, newSViv(pStorageStat->total_sync_in_bytes), 0);
                    cur = hv_store(storage, "success_sync_in_bytes",21, newSViv(pStorageStat->success_sync_in_bytes), 0);
                    cur = hv_store(storage, "total_sync_out_bytes",20, newSViv(pStorageStat->total_sync_out_bytes), 0);
                    cur = hv_store(storage, "success_sync_out_bytes",22, newSViv(pStorageStat->success_sync_out_bytes), 0);
                    cur = hv_store(storage, "total_file_open_count",21, newSViv(pStorageStat->total_file_open_count), 0);
                    cur = hv_store(storage, "success_file_open_count",23, newSViv(pStorageStat->success_file_open_count), 0);
                    cur = hv_store(storage, "total_file_read_count",21, newSViv(pStorageStat->total_file_read_count), 0);
                    cur = hv_store(storage, "success_file_read_count",23, newSViv(pStorageStat->success_file_read_count), 0);
                    cur = hv_store(storage, "total_file_write_count",22, newSViv(pStorageStat->total_file_write_count), 0);
                    cur = hv_store(storage, "success_file_write_count",24, newSViv(pStorageStat->success_file_write_count), 0);
                    cur = hv_store(storage, "last_heart_beat_time",20, newSViv(pStorageStat->last_heart_beat_time), 0);
                    cur = hv_store(storage, "last_source_update",18, newSViv(pStorageStat->last_source_update), 0);
                    cur = hv_store(storage, "last_sync_update",16, newSViv(pStorageStat->last_sync_update), 0);
                    cur = hv_store(storage, "last_synced_timestamp",21, newSViv(pStorageStat->last_synced_timestamp), 0);
                    cur = hv_store(hv1, pStorage->ip_addr, strlen(pStorage->ip_addr), newRV_noinc((SV*)storage), 0);
                }
                cur = hv_store(hv, pGroupStat->group_name, strlen(pGroupStat->group_name), newRV_noinc((SV *)hv1), 0);
            }
            RETVAL = hv;
        }else{
            XSRETURN_UNDEF;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_tracker_query_storage_store(char *group_name = NULL, HV *server = NULL)
    CODE:
        int result;
        int store_path_index;
        TrackerServerInfo *trackserver = NULL;
	TrackerServerInfo storage_server;

        if(server == NULL){
            trackserver = tracker_get_connection();
        }else{
            if(hv_trackerserver(server, trackserver) != 0){
                XSRETURN_UNDEF;
            }
        }

        if(group_name == NULL){
            result = tracker_query_storage_store_without_group(trackserver, &storage_server, &store_path_index);
        }else{
            result = tracker_query_storage_store_with_group(trackserver, group_name, &storage_server, &store_path_index);
        }
        
        if(result != 0){
            XSRETURN_UNDEF;
        }

        HV *hv = newHV();
        trackerserver_hv(&storage_server, hv);
        RETVAL = hv;
    OUTPUT:
        RETVAL

AV *
fastdfs_tracker_query_storage_store_list(char *group_name = NULL, HV *server = NULL)
    CODE:
        int result;
        int store_path_index;
        int storage_count;
        TrackerServerInfo *trackserver = NULL;
        TrackerServerInfo storage_servers[FDFS_MAX_SERVERS_EACH_GROUP];
        TrackerServerInfo *pServer;
	TrackerServerInfo *pServerEnd;
        
        if(server == NULL){
            trackserver = tracker_get_connection();
        }else{
            if(hv_trackerserver(server, trackserver) != 0){
                XSRETURN_UNDEF;
            }
        }

        if(group_name == NULL){
            result = tracker_query_storage_store_list_without_group(trackserver, storage_servers, FDFS_MAX_SERVERS_EACH_GROUP, &storage_count, &store_path_index);
        }else{
            result = tracker_query_storage_store_list_with_group(trackserver, group_name, storage_servers, FDFS_MAX_SERVERS_EACH_GROUP, &storage_count, &store_path_index);
        }
       
        if(result != 0){
            XSRETURN_UNDEF;
        }

        AV *av = newAV();
        pServerEnd = storage_servers + storage_count;
        for (pServer=storage_servers; pServer<pServerEnd; pServer++){
            HV *hv = newHV();
            trackerserver_hv(pServer, hv); 
            av_push(av, newRV_noinc((SV *)hv));
        }
        RETVAL = av;
    OUTPUT:
        RETVAL

HV *
fastdfs_tracker_query_storage_update(char *group_name, char *remote_filename, HV *server = NULL)
    CODE:
        HV *hv = perl_tracker_do_query_storage(group_name, remote_filename, TRACKER_PROTO_CMD_SERVICE_QUERY_UPDATE, server);
        if(hv == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_tracker_query_storage_fetch(char *group_name, char *remote_filename, HV *server = NULL)
    CODE:
        HV *hv = perl_tracker_do_query_storage(group_name, remote_filename, TRACKER_PROTO_CMD_SERVICE_QUERY_FETCH_ONE, server);
        if(hv == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

AV *
fastdfs_tracker_query_storage_list(char *group_name, char *remote_filename, HV *server = NULL)
    CODE:
        AV *av = perl_tracker_query_storage_list(group_name, remote_filename, server);
        if(av == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = av;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_tracker_query_storage_update1(const char *file_id, HV *server = NULL)
    CODE:
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
        char file_name[128];
        if(split_file_id(file_id, group_name, file_name)){
            XSRETURN_UNDEF;
        }
        HV *hv = perl_tracker_do_query_storage(group_name, file_name, TRACKER_PROTO_CMD_SERVICE_QUERY_UPDATE, server);
        if(hv == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_tracker_query_storage_fetch1(char *file_id, HV *server = NULL)
    CODE:
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
        char file_name[128];
        if(split_file_id(file_id, group_name, file_name)){
            XSRETURN_UNDEF;
        }

        HV *hv = perl_tracker_do_query_storage(group_name, file_name, TRACKER_PROTO_CMD_SERVICE_QUERY_FETCH_ONE, server);
        if(hv == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

AV *
fastdfs_tracker_query_storage_list1(char *file_id, HV *server = NULL)
    CODE:
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
        char file_name[128];
        if(split_file_id(file_id, group_name, file_name)){
            XSRETURN_UNDEF;
        }
        AV *av = perl_tracker_query_storage_list( group_name, file_name, server);
        if(av == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = av;
        }
    OUTPUT:
        RETVAL
       
bool
fastdfs_tracker_delete_storage(char *group_name, char *storage_ip)
    CODE:
        if(tracker_delete_storage(&g_tracker_group, group_name, storage_ip) == 0){
            RETVAL = TRUE;
        }else{ 
            RETVAL = FALSE;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_storage_upload_by_filename(char *local_filename, char *group_name=NULL)
    CODE:
        HV *hv = newHV();
        hv = perl_fdfs_storage_upload_file(local_filename,group_name);
        if(hv == NULL){
            XSRETURN_UNDEF;
        }else{
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_storage_upload_by_filebuff(SV *data, char *ext_name, char *group_name=NULL)
    CODE:
        int result;
        int data_len;
        int store_path_index;
        char remote_filename[128];
        char remote_group[FDFS_GROUP_NAME_MAX_LEN + 1];
        TrackerServerInfo *trackserver = NULL;
        TrackerServerInfo storage_server;

        trackserver = tracker_get_connection();
        if(group_name == NULL){
            result = tracker_query_storage_store_without_group(trackserver, &storage_server, &store_path_index);
        }else{
            strcpy(remote_group, group_name);
            result = tracker_query_storage_store_with_group(trackserver, group_name, &storage_server, &store_path_index);
        }
        if(result != 0){
            XSRETURN_UNDEF;
        }
        data_len = SvLEN(data);
        result = storage_do_upload_file(trackserver, &storage_server, store_path_index, STORAGE_PROTO_CMD_UPLOAD_FILE, FDFS_UPLOAD_BY_BUFF, \
                               SvPV_nolen(data), NULL, data_len, NULL, NULL, ext_name, NULL, 0, remote_group, remote_filename);
        if(result != 0){
            XSRETURN_UNDEF;
        }

        HV *hv = newHV();
        SV **cur = NULL;
        cur = hv_store(hv, "group_name", 10, newSVpv(remote_group,0), 0);
        cur = hv_store(hv, "file_name",  9, newSVpv(remote_filename,0), 0);
        cur = NULL;
        RETVAL = hv;
    OUTPUT:
        RETVAL

bool
fastdfs_storage_delete_file(const char *group_name, const char *file_name)
    CODE:
        int result; 
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_delete_file(trackserver, NULL, group_name, file_name);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

bool
fastdfs_storage_delete_file1(const char *file_id)
    CODE:
        int result;
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
        char file_name[128];
        if(split_file_id(file_id, group_name, file_name)){
            XSRETURN_UNDEF;
        }
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_delete_file(trackserver, NULL, group_name, file_name);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

bool
fastdfs_storage_download_file_to_file(const char *group_name, const char *file_name, const char *local_filename)
    CODE:
        int result;
        int64_t file_size;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_download_file_to_file( trackserver, NULL, group_name, file_name, local_filename, &file_size); 
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

bool
fastdfs_storage_download_file_to_file1(const char *file_id, const char *local_filename)
    CODE:
        int result;
        int64_t file_size;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_download_file_to_file1(trackserver, NULL, file_id, local_filename, &file_size);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

SV *
fastdfs_storage_download_file_to_buff(const char *group_name, const char *file_name)
    CODE:
        int result;
        int64_t buff_size;
        char *buff;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_download_file_to_buff(trackserver, NULL, group_name, file_name, &buff, &buff_size);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            SV * sv = newSVpv(buff, buff_size);
            RETVAL = sv;
        }
    OUTPUT:
        RETVAL

SV *
fastdfs_storage_download_file_to_buff1(const char *file_id)
    CODE:
        int result;
        int64_t buff_size;
        char *buff;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_download_file_to_buff1(trackserver, NULL, file_id, &buff, &buff_size);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            SV * sv = newSVpv(buff, buff_size);
            RETVAL = sv;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_get_file_info(const char *group_name, const char *file_name)
    CODE:
        int result;
        FDFSFileInfo file_info;
        result = fdfs_get_file_info(group_name, file_name, &file_info);
         if(result != 0){
            XSRETURN_UNDEF;
        }else{
            HV *hv = newHV();
            SV **cur = NULL;
            cur = hv_store(hv, "create_timestamp", 16, newSViv(file_info.create_timestamp), 0);
            cur = hv_store(hv, "file_size",        9,  newSViv(file_info.file_size), 0);
            cur = hv_store(hv, "source_ip_addr",   14, newSVpv(file_info.source_ip_addr,0), 0);
            cur = hv_store(hv, "crc32",            5,  newSViv(file_info.crc32), 0);
            cur = NULL;
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL

HV *
fastdfs_get_file_info1(const char *file_id)
    CODE:
        int result;
        FDFSFileInfo file_info;
        result = fdfs_get_file_info1(file_id, &file_info);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            HV *hv = newHV();
            SV **cur = NULL;
            cur = hv_store(hv, "create_timestamp", 16, newSViv(file_info.create_timestamp), 0);
            cur = hv_store(hv, "file_size",        9,  newSViv(file_info.file_size), 0);
            cur = hv_store(hv, "source_ip_addr",   14, newSVpv(file_info.source_ip_addr,0), 0);
            cur = hv_store(hv, "crc32",            5,  newSViv(file_info.crc32), 0);
            cur = NULL;
            RETVAL = hv;
        }
    OUTPUT:
        RETVAL       

bool
fastdfs_storage_file_exist(const char *group_name, const char *file_name)
    CODE:
        int result;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_file_exist(trackserver, NULL, group_name, file_name);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

bool
fastdfs_storage_file_exist1(const char *file_id)
    CODE:
        int result;
        TrackerServerInfo *trackserver = NULL;
        trackserver = tracker_get_connection();
        result = storage_file_exist1(trackserver, NULL, file_id);
        if(result != 0){
            XSRETURN_UNDEF;
        }else{
            RETVAL = 1;
        }
    OUTPUT:
        RETVAL

