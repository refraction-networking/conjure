
#ifndef _TD_LOADKEY_H_
#define _TD_LOADKEY_H_ 1

// NOTE: this is a holdover from detect.c -- I am not sure what the correct params are.
#define PF_BURST_SIZE 16

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

    typedef struct zbalance_ipc_runner zbalance_ipc_runner;

    int create_runner(struct zbalance_ipc_runner **ptr, int cluster_id, int queue_id, int buf_len);

    int next_packet_burst(zbalance_ipc_runner *runner);

    int next_packet(zbalance_ipc_runner *runner);

    int set_filter(zbalance_ipc_runner *runner, char *filter);

    int unset_filter(zbalance_ipc_runner *runner);

    int close(zbalance_ipc_runner *runner);

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _TD_LOADKEY_H_
