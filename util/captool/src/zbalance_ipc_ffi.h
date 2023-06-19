
#ifndef _TD_LOADKEY_H_
#define _TD_LOADKEY_H_ 1

// NOTE: this is a holdover from detect.c -- I am not sure what the correct params are.
#define PF_BURST_SIZE 16

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

    typedef struct zbalance_ipc_runner zbalance_ipc_runner;

    typedef struct zbalance_packet zbalance_packet;

    /// @brief create a runner object that will maintain state for a pfring zbalance ipc ingest queue
    /// @param ptr a pointer which will be set to point to the new runner on success
    /// @param cluster_id the pfring zbalance cluster ID to attach onto
    /// @param queue_id the pfring zbalance queue ID to read from
    /// @param buf_len the length of the packet buffer for calls to `next_packet_burst` cannot be changed after initialization.
    /// @return 0 on success, a negative value otherwise.
    int init_runner(struct zbalance_ipc_runner **ptr, int cluster_id, int queue_id, int buf_len);

    /// @brief Read the next packet from the queue
    /// @param runner  The C struct managing this queue
    /// @return 1 on success, 0 on empty queue (non-blocking only), a negative value otherwise.
    int next_packet_burst(zbalance_ipc_runner *runner);

    /// @brief Read a burst of `buf_len` packets from the queue.
    /// @param runner The C struct managing this queue
    /// @return n packets read on success, 0 on empty queue (non-blocking only), a negative value otherwise.
    int next_packet(zbalance_ipc_runner *runner, zbalance_packet *packet);

    /// @brief Apply a BPF filter from text.
    /// @param runner The C struct managing this queue
    /// @return 0 on success, a negative value otherwise.
    int set_filter(zbalance_ipc_runner *runner, char *filter);

    /// @brief Remove the BPF filter.
    /// @param runner The C struct managing this queue
    /// @return 0 on success, a negative value otherwise.
    int unset_filter(zbalance_ipc_runner *runner);

    /// @brief cleanup after a runner object, detaching from pfring and freeing resources
    /// @param runner the runner object to be cleaned
    /// @return 0 on success, a negative value otherwise.
    int close(zbalance_ipc_runner *runner);

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _TD_LOADKEY_H_
