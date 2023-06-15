

#include <stdint.h>
// #include <stdio.h>
// #include <errno.h>
#include "zbalance_ipc_ffi.h"
#include "pfring_zc.h"

struct zbalance_ipc_runner
{
    pfring_zc_queue *g_queue;
    pfring_zc_buffer_pool *g_pool;
    pfring_zc_pkt_buff **g_buf;

    int buf_len; // Defaults to PF_BURST_SIZE
    int cluster_id;
    int queue_id;
};

struct zbalance_packet
{
    int size;
    int *bytes;
}

/// @brief create a runner object that will maintain state for a pfring zbalance ipc ingest queue
/// @param ptr a pointer which will be set to point to the new runner on success
/// @param cluster_id the pfring zbalance cluster ID to attach onto
/// @param queue_id the pfring zbalance queue ID to read from
/// @param buf_len the length of the packet buffer for calls to `next_packet_burst` cannot be changed after initialization.
/// @return 0 on success, a negative value otherwise.
int create_runner(struct zbalance_ipc_runner **ptr, int cluster_id, int queue_id, int buf_len)
{
    if (buf_len < 1)
        buf_len = PF_BURST_SIZE;

    pfring_zc_pkt_buff **g_buf = malloc(sizeof(pfring_zc_pkt_buff *) * buf_len);

    zbalance_ipc_runner *runner = maloc(sizeof(zbalance_ipc_runner));
    runner->g_queue = 0;
    runner->g_buf = g_buf;
    runner->g_pool = 0;
    runner->buf_len = buf_len;
    runner->cluster_id = cluster_id;
    runner->queue_id = queue_id;

    pfring_zc_pkt_buff *g_buf[buf_len];

    char cluster_iface_id[200];
    sprintf(cluster_iface_id, "zc:%d@%d", runner->cluster_id, runner->queue_id);
    if (!(runner->g_queue = pfring_zc_ipc_attach_queue(cluster_id, queue_id, rx_only)))
    {
        // fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] opening %s "
        //                 "(%d, %d)\n",
        //         strerror(errno), cluster_iface_id, cluster_id, queue_id);
        return (-1);
    }

    if (!(runner->g_pool = pfring_zc_ipc_attach_buffer_pool(cluster_id, queue_id)))
    {
        // fprintf(stderr,
        //         "pfring_zc_ipc_attach_buffer_pool error [%s] opening %s\n",
        //         strerror(errno), cluster_iface_id);
        return (-1);
    }

    for (int i = 0; i < runner->buf_len; i++)
    {
        if (!(runner->g_buf[i] = pfring_zc_get_packet_handle_from_pool(runner->g_pool)))
        {
            // fprintf(stderr,
            //         "pfring_zc_get_packet_handle_from_pool error [%s] "
            //         "opening %s\n",
            //         strerror(errno), cluster_iface_id);
            return (-1);
        }
    }

    return 0;
}

/// @brief Apply a BPF filter from text.
/// @param runner The C struct managing this queue
/// @return 0 on success, a negative value otherwise.
int set_filter(zbalance_ipc_runner *runner, char *filter)
{
    return pfring_zc_set_bpf_filter(runner->g_queue, filter);
}

/// @brief Remove the BPF filter.
/// @param runner The C struct managing this queue
/// @return 0 on success, a negative value otherwise.
int unset_filter(zbalance_ipc_runner *runner)
{
    return pfring_zc_remove_bpf_filter(runner->g_queue);
}

/// @brief Read the next packet from the queue
/// @param runner  The C struct managing this queue
/// @return 1 on success, 0 on empty queue (non-blocking only), a negative value otherwise.
int next_packet(zbalance_ipc_runner *runner, zbalance_packet *packet)
{
    int res = pfring_zc_recv_pkt(runner->g_queue, runner->g_buf, 0);
    packet->size = runner->g_buf[0]->size;
    packet->bytes = pfring_zc_pkt_buff_data(runner->g_buf[0], runner->g_ring);
    return res;
}

/// @brief Read a burst of `buf_len` packets from the queue.
/// @param runner The C struct managing this queue
/// @return 1 on success, 0 on empty queue (non-blocking only), a negative value otherwise.
int next_packet_burst(zbalance_ipc_runner *runner)
{
    return pfring_zc_recv_pkt_burst(runner->g_queue, runner->g_buf, PF_BURST_SIZE, 0);
}

/// @brief cleanup after a runner object, detaching from pfring and freeing resources
/// @param runner the runner object to be cleaned
/// @return 0 on success, a negative value otherwise.
int close(zbalance_ipc_runner *runner)
{
    if (runner = 0)
        return 0;

    // Stop receiving from the queue
    pfring_zc_queue_breakloop(runner->g_queue);

    // drain the buffer
    for (int i = 0; i < PF_BURST_SIZE; i++)
    {
        pfring_zc_release_packet_handle_to_pool(runner->g_pool, runner->g_buf[i]);
    }

    // detach from the queue making it available to other zbalance_ipc queue handlers
    pfring_zc_ipc_detach_queue(runner->g_queue);
    pfring_zc_ipc_detach_buffer_pool(runner->g_pool);

    // free the buffer and our runner object
    if (runner->g_buf != 0)
        free(runner->g_buf);

    free(runner);
    runner = 0;

    return 0;
}