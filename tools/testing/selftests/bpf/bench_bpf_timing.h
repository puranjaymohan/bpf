/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Userspace API for BPF batch-timing benchmarks.
 *
 * BPF program includes progs/bench_bpf_timing.bpf.h for the timing arrays
 * and BENCH_BPF_LOOP macro.  Userspace includes this header, wires up the
 * skeleton BSS via BENCH_TIMING_INIT, and calls bpf_bench_calibrate to
 * auto-calibrate batch_iters with proportionality verification.
 */

#ifndef __BENCH_BPF_TIMING_H__
#define __BENCH_BPF_TIMING_H__

#include <stdbool.h>
#include <linux/types.h>
#include "bench.h"

/* Must match progs/bench_bpf_timing.bpf.h */
#define BENCH_NR_SAMPLES	4096
#define BENCH_NR_CPUS		256

/* Callback to run the BPF program once (wraps bpf_prog_test_run_opts). */
typedef void (*bpf_bench_run_fn)(void *ctx);

struct bpf_bench_timing {
	__u64 (*samples)[BENCH_NR_SAMPLES];	/* skel->bss->timing_samples */
	__u32 *idx;				/* skel->bss->timing_idx */
	volatile __u32 *timing_enabled;		/* &skel->bss->timing_enabled */
	volatile __u32 *batch_iters_bss;	/* &skel->bss->batch_iters */
	__u32 batch_iters;
	__u32 target_samples;
	__u32 nr_cpus;
	bool done;
};

/* Wire up timing state from skeleton BSS.  Call after load. */
#define BENCH_TIMING_INIT(t, skel, iters) do {				\
	(t)->samples = (skel)->bss->timing_samples;			\
	(t)->idx = (skel)->bss->timing_idx;				\
	(t)->timing_enabled = &(skel)->bss->timing_enabled;		\
	(t)->batch_iters_bss = &(skel)->bss->batch_iters;		\
	(t)->batch_iters = (iters);					\
	(t)->target_samples = 200;					\
	(t)->nr_cpus = env.nr_cpus;					\
	(t)->done = false;						\
} while (0)

/* bench->measure(): enables timing after warmup, auto-stops when done. */
void bpf_bench_timing_measure(struct bpf_bench_timing *t, struct bench_res *res);

/* bench->report_final(): collect samples, print stats + histogram. */
void bpf_bench_timing_report(struct bpf_bench_timing *t, const char *name, const char *desc);

/*
 * Auto-calibrate batch_iters targeting ~10ms/batch and verify
 * proportionality (2N iterations should take 2x the time of N).
 * Sets t->batch_iters and *t->batch_iters_bss.
 */
void bpf_bench_calibrate(struct bpf_bench_timing *t, bpf_bench_run_fn run_fn, void *ctx);

#endif /* __BENCH_BPF_TIMING_H__ */
