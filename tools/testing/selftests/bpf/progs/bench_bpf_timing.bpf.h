/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Shared timing infrastructure for BPF benchmarks.
 *
 * Each BPF benchmark includes this header to get per-CPU timing arrays
 * and the BENCH_BPF_LOOP() macro for batch timing.  Userspace reads the
 * timing arrays from the skeleton's BSS via bench_bpf_timing.h.
 */

#ifndef __BENCH_BPF_TIMING_BPF_H__
#define __BENCH_BPF_TIMING_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BENCH_NR_SAMPLES	4096
#define BENCH_NR_CPUS		256
#define BENCH_CPU_MASK		(BENCH_NR_CPUS - 1)

__u64 __attribute__((__aligned__(256))) timing_samples[BENCH_NR_CPUS][BENCH_NR_SAMPLES];
__u32 __attribute__((__aligned__(256))) timing_idx[BENCH_NR_CPUS];

volatile __u32 batch_iters;
volatile __u32 timing_enabled;

/* Record one batch timing sample.  Fills up to BENCH_NR_SAMPLES then stops. */
static __always_inline void bench_record_sample(__u64 elapsed_ns)
{
	__u32 cpu, idx;

	if (!timing_enabled)
		return;

	cpu = bpf_get_smp_processor_id() & BENCH_CPU_MASK;
	idx = timing_idx[cpu];

	if (idx >= BENCH_NR_SAMPLES)
		return;

	timing_samples[cpu][idx] = elapsed_ns;
	timing_idx[cpu] = idx + 1;
}

/*
 * BENCH_BPF_LOOP(body, reset) - batch timing macro.
 *
 * @body:  expression to measure; its return value (int) is stored in
 *         __bench_result, which the reset block can reference.
 * @reset: statement block executed after each timed iteration to undo
 *         side effects (e.g., strip encapsulation, reset map entries).
 *         May reference __bench_result.  Use ({}) for an empty reset.
 *
 * Measures batch_iters iterations bracketed by bpf_ktime_get_ns(),
 * records the elapsed time, then runs one extra untimed iteration
 * whose return value the macro evaluates to (for validation by userspace).
 */
#define BENCH_BPF_LOOP(body, reset) ({					\
	__u64 __bench_start = bpf_ktime_get_ns();			\
	int __bench_result;						\
									\
	bpf_repeat(batch_iters) {					\
		__bench_result = (body);				\
		reset;							\
	}								\
									\
	bench_record_sample(bpf_ktime_get_ns() - __bench_start);	\
									\
	/* Untimed final iteration - result returned for validation */	\
	__bench_result = (body);					\
	__bench_result;							\
})

#endif /* __BENCH_BPF_TIMING_BPF_H__ */
