# Health Supervisor and Systemd Watchdog

The health supervisor periodically checks the agent's subsystem health and triggers a process restart if the agent remains unhealthy for too long. When running under systemd, it also sends `WATCHDOG=1` notifications.

## Health Checkers

| Checker | What it checks         | Failure condition               |
| ------- | ---------------------- | ------------------------------- |
| `mqtt`  | MQTT broker connection | `client.IsConnected() == false` |

Additional checkers can be registered at startup via `supervisor.Register()`.

## Behavior

1. The supervisor runs a periodic ticker at the configured interval
2. Each tick, all registered checkers are polled
3. If any checker reports unhealthy, the unhealthy timer starts
4. If the agent stays unhealthy longer than the timeout, the process is restarted via `syscall.Exec()`
5. If all checkers recover before the timeout, the unhealthy timer resets

## Systemd Watchdog Integration

When the `NOTIFY_SOCKET` environment variable is set (indicating the agent is running under systemd with `WatchdogSec` configured):

- The agent sends periodic `WATCHDOG=1` notifications via the unix datagram socket
- Notifications are only sent when the agent is healthy
- If the agent becomes unhealthy and stops notifying, systemd will kill and restart the process

### Example systemd unit

```ini
[Unit]
Description=Magistrala Agent

[Service]
Type=notify
ExecStart=/usr/local/bin/agent
WatchdogSec=30
Restart=always

[Install]
WantedBy=multi-user.target
```

## Configuration

### Environment Variables

| Variable                     | Default | Description                                     |
| ---------------------------- | ------- | ----------------------------------------------- |
| `MG_AGENT_WATCHDOG_INTERVAL` | `0`     | Health check interval; `0` disables supervision |
| `MG_AGENT_WATCHDOG_TIMEOUT`  | `60s`   | How long unhealthy before triggering restart    |

## HTTP Endpoints

### Health check

```bash
curl -s http://localhost:9999/health | jq .
```

**Response:**

```json
{
  "status": "pass",
  "version": "0.0.0",
  "commit": "ffffffff",
  "description": "agent service",
  "build_time": "1970-01-01_00:00:00",
  "instance_id": ""
}
```

### Prometheus metrics

```bash
curl -s http://localhost:9999/metrics
```

**Response:**

```txt
# HELP agent_api_request_count Number of requests received.
# TYPE agent_api_request_count counter
agent_api_request_count{method="command_secret"} 6
agent_api_request_count{method="config"} 8
agent_api_request_count{method="terminal"} 6
agent_api_request_count{method="update_liveness"} 315
# HELP agent_api_request_latency_microseconds Total duration of requests in microseconds.
# TYPE agent_api_request_latency_microseconds summary
agent_api_request_latency_microseconds{method="command_secret",quantile="0.5"} 4.8131e-05
agent_api_request_latency_microseconds{method="command_secret",quantile="0.9"} 9.6383e-05
agent_api_request_latency_microseconds{method="command_secret",quantile="0.99"} 9.6383e-05
agent_api_request_latency_microseconds_sum{method="command_secret"} 0.00033213700000000004
agent_api_request_latency_microseconds_count{method="command_secret"} 6
agent_api_request_latency_microseconds{method="config",quantile="0.5"} 9.6171e-05
agent_api_request_latency_microseconds{method="config",quantile="0.9"} 0.000184515
agent_api_request_latency_microseconds{method="config",quantile="0.99"} 0.000184515
agent_api_request_latency_microseconds_sum{method="config"} 0.0008824780000000001
agent_api_request_latency_microseconds_count{method="config"} 8
agent_api_request_latency_microseconds{method="terminal",quantile="0.5"} 4.3531e-05
agent_api_request_latency_microseconds{method="terminal",quantile="0.9"} 0.000945491
agent_api_request_latency_microseconds{method="terminal",quantile="0.99"} 0.000945491
agent_api_request_latency_microseconds_sum{method="terminal"} 0.0012051910000000002
agent_api_request_latency_microseconds_count{method="terminal"} 6
agent_api_request_latency_microseconds{method="update_liveness",quantile="0.5"} 1.2424e-05
agent_api_request_latency_microseconds{method="update_liveness",quantile="0.9"} 5.322e-05
agent_api_request_latency_microseconds{method="update_liveness",quantile="0.99"} 0.000103354
agent_api_request_latency_microseconds_sum{method="update_liveness"} 0.007146967999999997
agent_api_request_latency_microseconds_count{method="update_liveness"} 315
# HELP go_gc_duration_seconds A summary of the wall-time pause (stop-the-world) duration in garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 5.2469e-05
go_gc_duration_seconds{quantile="0.25"} 5.8792e-05
go_gc_duration_seconds{quantile="0.5"} 0.000137268
go_gc_duration_seconds{quantile="0.75"} 0.000150681
go_gc_duration_seconds{quantile="1"} 0.000182847
go_gc_duration_seconds_sum 0.000700169
go_gc_duration_seconds_count 6
# HELP go_gc_gogc_percent Heap size target percentage configured by the user, otherwise 100. This value is set by the GOGC environment variable, and the runtime/debug.SetGCPercent function. Sourced from /gc/gogc:percent.
# TYPE go_gc_gogc_percent gauge
go_gc_gogc_percent 100
# HELP go_gc_gomemlimit_bytes Go runtime memory limit configured by the user, otherwise math.MaxInt64. This value is set by the GOMEMLIMIT environment variable, and the runtime/debug.SetMemoryLimit function. Sourced from /gc/gomemlimit:bytes.
# TYPE go_gc_gomemlimit_bytes gauge
go_gc_gomemlimit_bytes 9.223372036854776e+18
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 24
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.26.4-X:nodwarf5"} 1
# HELP go_memstats_alloc_bytes Number of bytes allocated in heap and currently in use. Equals to /memory/classes/heap/objects:bytes.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 1.961496e+06
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated in heap until now, even if released already. Equals to /gc/heap/allocs:bytes.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 6.99192e+06
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table. Equals to /memory/classes/profiling/buckets:bytes.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.452815e+06
# HELP go_memstats_frees_total Total number of heap objects frees. Equals to /gc/heap/frees:objects + /gc/heap/tiny/allocs:objects.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 50935
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata. Equals to /memory/classes/metadata/other:bytes.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 3.395312e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and currently in use, same as go_memstats_alloc_bytes. Equals to /memory/classes/heap/objects:bytes.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 1.961496e+06
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used. Equals to /memory/classes/heap/released:bytes + /memory/classes/heap/free:bytes.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 3.424256e+06
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use. Equals to /memory/classes/heap/objects:bytes + /memory/classes/heap/unused:bytes
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 3.85024e+06
# HELP go_memstats_heap_objects Number of currently allocated objects. Equals to /gc/heap/objects:objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 11786
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS. Equals to /memory/classes/heap/released:bytes.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 2.490368e+06
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system. Equals to /memory/classes/heap/objects:bytes + /memory/classes/heap/unused:bytes + /memory/classes/heap/released:bytes + /memory/classes/heap/free:bytes.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 7.274496e+06
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.7812584662391562e+09
# HELP go_memstats_mallocs_total Total number of heap objects allocated, both live and gc-ed. Semantically a counter version for go_memstats_heap_objects gauge. Equals to /gc/heap/allocs:objects + /gc/heap/tiny/allocs:objects.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 62721
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures. Equals to /memory/classes/metadata/mcache/inuse:bytes.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 36736
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system. Equals to /memory/classes/metadata/mcache/inuse:bytes + /memory/classes/metadata/mcache/free:bytes.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 48216
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures. Equals to /memory/classes/metadata/mspan/inuse:bytes.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 167680
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system. Equals to /memory/classes/metadata/mspan/inuse:bytes + /memory/classes/metadata/mspan/free:bytes.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 179520
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place. Equals to /gc/heap/goal:bytes.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 4.248298e+06
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations. Equals to /memory/classes/other:bytes.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 2.155889e+06
# HELP go_memstats_stack_inuse_bytes Number of bytes obtained from system for stack allocator in non-CGO environments. Equals to /memory/classes/heap/stacks:bytes.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 1.114112e+06
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator. Equals to /memory/classes/heap/stacks:bytes + /memory/classes/os-stacks:bytes.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 1.114112e+06
# HELP go_memstats_sys_bytes Number of bytes obtained from system. Equals to /memory/classes/total:byte.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 1.562036e+07
# HELP go_sched_gomaxprocs_threads The current runtime.GOMAXPROCS setting, or the number of operating system threads that can execute user-level Go code simultaneously. Sourced from /sched/gomaxprocs:threads.
# TYPE go_sched_gomaxprocs_threads gauge
go_sched_gomaxprocs_threads 16
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 15
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.23
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 524287
# HELP process_network_receive_bytes_total Number of bytes received by the process over the network.
# TYPE process_network_receive_bytes_total counter
process_network_receive_bytes_total 113277
# HELP process_network_transmit_bytes_total Number of bytes sent by the process over the network.
# TYPE process_network_transmit_bytes_total counter
process_network_transmit_bytes_total 70609
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 11
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 2.4420352e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.78125796441e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 1.314848768e+09
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 1
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
```

Exposes Prometheus counters and latency histograms for all service methods.
