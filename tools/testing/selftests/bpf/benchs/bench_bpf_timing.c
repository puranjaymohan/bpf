// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Shared timing infrastructure for BPF batch-timing benchmarks.
 *
 * Collects per-CPU timing samples from BPF BSS arrays, computes
 * percentile statistics, and prints a fixed-width-bin histogram.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "bench_bpf_timing.h"
#include "bpf_util.h"

#define HIST_BAR_WIDTH	40

struct timing_stats {
	double min, max;
	double p1, p5, p25, median, p75, p90, p95, p99;
	double mean, stddev;
	int count;
};

static int cmp_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;

	if (da < db)
		return -1;
	if (da > db)
		return 1;
	return 0;
}

static double percentile(const double *sorted, int n, double pct)
{
	int idx = (int)(n * pct / 100.0);

	if (idx >= n)
		idx = n - 1;
	return sorted[idx];
}

static int collect_samples(struct bpf_bench_timing *t,
			   double *out, int max_out)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u32 timed_iters = t->batch_iters;
	unsigned int cpu;
	int total = 0;

	if (nr_cpus > BENCH_NR_CPUS)
		nr_cpus = BENCH_NR_CPUS;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		__u32 count = t->idx[cpu];
		__u32 i;

		if (count > BENCH_NR_SAMPLES)
			count = BENCH_NR_SAMPLES;

		for (i = 0; i < count && total < max_out; i++) {
			__u64 sample = t->samples[cpu][i];

			if (sample == 0)
				continue;
			out[total++] = (double)sample / timed_iters;
		}
	}

	qsort(out, total, sizeof(double), cmp_double);
	return total;
}

static void compute_stats(const double *sorted, int n,
			  struct timing_stats *s)
{
	double sum = 0, var_sum = 0;
	int i;

	memset(s, 0, sizeof(*s));
	s->count = n;

	if (n == 0)
		return;

	s->min    = sorted[0];
	s->max    = sorted[n - 1];
	s->p1     = percentile(sorted, n, 1);
	s->p5     = percentile(sorted, n, 5);
	s->p25    = percentile(sorted, n, 25);
	s->median = sorted[n / 2];
	s->p75    = percentile(sorted, n, 75);
	s->p90    = percentile(sorted, n, 90);
	s->p95    = percentile(sorted, n, 95);
	s->p99    = percentile(sorted, n, 99);

	for (i = 0; i < n; i++)
		sum += sorted[i];
	s->mean = sum / n;

	for (i = 0; i < n; i++) {
		double d = sorted[i] - s->mean;

		var_sum += d * d;
	}
	s->stddev = n > 1 ? sqrt(var_sum / (n - 1)) : 0;
}

/* Fixed bin width avoids sub-ns bins that make tight distributions look spread. */
static double select_bin_width(double range)
{
	if (range < 20)
		return 1;
	if (range < 100)
		return 5;
	if (range < 500)
		return 10;
	if (range < 2000)
		return 50;
	return 100;
}

static void print_histogram(const double *sorted, int n,
			    const struct timing_stats *s)
{
	double range = s->p99 - s->p1;
	double bin_w = select_bin_width(range);
	double lo = floor(s->p1 / bin_w) * bin_w;
	double hi = ceil(s->p99 / bin_w) * bin_w;
	int nr_bins, prec;
	__u64 below = 0, above = 0, max_bin = 0;
	__u64 *bins;
	int i, j, bar;

	if (hi <= lo)
		hi = lo + bin_w;

	nr_bins = (int)((hi - lo) / bin_w);
	if (nr_bins < 1)
		nr_bins = 1;
	if (nr_bins > 100)
		nr_bins = 100;

	bins = calloc(nr_bins, sizeof(*bins));
	if (!bins)
		return;

	for (i = 0; i < n; i++) {
		if (sorted[i] < lo) {
			below++;
		} else if (sorted[i] >= hi) {
			above++;
		} else {
			int b = (int)((sorted[i] - lo) / bin_w);

			if (b >= nr_bins)
				b = nr_bins - 1;
			bins[b]++;
			if (bins[b] > max_bin)
				max_bin = bins[b];
		}
	}

	prec = bin_w >= 1.0 ? 0 : (bin_w >= 0.1 ? 1 : 2);

	printf("\n  Distribution (ns/op):\n");

	if (below > 0)
		printf("  %8s : %-8llu  (below range)\n", "<p1",
		       (unsigned long long)below);

	for (i = 0; i < nr_bins; i++) {
		double edge = lo + i * bin_w;

		bar = max_bin > 0
			? (int)(bins[i] * HIST_BAR_WIDTH / max_bin)
			: 0;

		printf("  %8.*f : %-8llu  |", prec, edge,
		       (unsigned long long)bins[i]);
		for (j = 0; j < HIST_BAR_WIDTH; j++)
			putchar(j < bar ? '*' : ' ');
		printf("|\n");
	}

	if (above > 0)
		printf("  %8s : %-8llu  (above range)\n", ">p99",
		       (unsigned long long)above);

	free(bins);
}

static int warmup_ticks;

void bpf_bench_timing_measure(struct bpf_bench_timing *t,
			      struct bench_res *res)
{
	unsigned int nr_cpus;
	__u32 total_samples;
	int i;

	warmup_ticks++;

	if (warmup_ticks < env.warmup_sec)
		return;

	if (warmup_ticks == env.warmup_sec) {
		*t->timing_enabled = 1;
		return;
	}

	/* Check total samples across all CPUs (handles migration + few producers) */
	nr_cpus = bpf_num_possible_cpus();
	if (nr_cpus > BENCH_NR_CPUS)
		nr_cpus = BENCH_NR_CPUS;

	total_samples = 0;
	for (i = 0; i < (int)nr_cpus; i++) {
		__u32 cnt = t->idx[i];

		if (cnt > BENCH_NR_SAMPLES)
			cnt = BENCH_NR_SAMPLES;
		total_samples += cnt;
	}

	if (total_samples >= (__u32)env.producer_cnt * t->target_samples &&
	    !t->done) {
		t->done = true;
		*t->timing_enabled = 0;
		bench_force_done();
	}
}

void bpf_bench_timing_report(struct bpf_bench_timing *t,
			     const char *name, const char *description)
{
	__u32 timed_iters = t->batch_iters;
	int max_out = BENCH_NR_CPUS * BENCH_NR_SAMPLES;
	struct timing_stats s;
	double *all;
	int total, prec;

	printf("\nScenario: %s", name);
	if (description)
		printf(" - %s", description);
	printf("\n");
	printf("Batch size: %u iterations/invocation (+1 for validation)\n",
	       t->batch_iters);

	all = calloc(max_out, sizeof(*all));
	if (!all) {
		fprintf(stderr, "failed to allocate timing buffer\n");
		return;
	}

	total = collect_samples(t, all, max_out);

	if (total == 0) {
		printf("\nNo in-BPF timing samples collected.\n");
		free(all);
		return;
	}

	compute_stats(all, total, &s);

	if (s.p99 - s.p1 >= 10.0)
		prec = 1;
	else if (s.p99 - s.p1 >= 1.0)
		prec = 2;
	else
		prec = 3;

	printf("\nIn-BPF timing: %d samples, %u ops/batch\n",
	       total, timed_iters);
	printf("  median %.*f ns/op, stddev %.*f, CV %.2f%% [min %.*f, max %.*f]\n",
	       prec, s.median, prec, s.stddev,
	       s.mean > 0 ? s.stddev / s.mean * 100.0 : 0.0,
	       prec, s.min, prec, s.max);
	printf("  p50 %.*f, p75 %.*f, p90 %.*f, p95 %.*f, p99 %.*f\n",
	       prec, s.median, prec, s.p75, prec, s.p90, prec, s.p95,
	       prec, s.p99);

	if (total < 200)
		printf("  WARNING: only %d samples - tail percentiles may be unreliable\n",
		       total);

	if (s.median > s.p1 &&
	    (s.p99 - s.median) > 3.0 * (s.median - s.p1))
		printf("  NOTE: right-skewed distribution (tail %.1fx the body)\n",
		       (s.p99 - s.median) / (s.median - s.p1));

	print_histogram(all, total, &s);

	free(all);
}

#define CALIBRATE_SEED_BATCH	100
#define CALIBRATE_MIN_BATCH	100
#define CALIBRATE_MAX_BATCH	10000000
#define CALIBRATE_TARGET_MS	10
#define CALIBRATE_RUNS		5
#define PROPORTIONALITY_TOL	0.02	/* 2% */

static void reset_timing(struct bpf_bench_timing *t)
{
	*t->timing_enabled = 0;
	memset(t->samples, 0,
	       sizeof(__u64) * BENCH_NR_CPUS * BENCH_NR_SAMPLES);
	memset(t->idx, 0, sizeof(__u32) * BENCH_NR_CPUS);
}

/* Run the BPF program @runs times at @iters batch_iters, return median elapsed ns. */
static __u64 measure_elapsed(struct bpf_bench_timing *t,
			     bpf_bench_run_fn run_fn, void *run_ctx,
			     __u32 iters, int runs)
{
	__u64 buf[CALIBRATE_RUNS];
	int n = 0, i, j;

	reset_timing(t);
	*t->batch_iters_bss = iters;
	*t->timing_enabled = 1;

	for (i = 0; i < runs; i++)
		run_fn(run_ctx);

	*t->timing_enabled = 0;

	for (i = 0; i < BENCH_NR_CPUS && n < runs; i++) {
		__u32 cnt = t->idx[i];

		for (j = 0; j < (int)cnt && n < runs; j++)
			buf[n++] = t->samples[i][j];
	}

	if (n == 0)
		return 0;

	/* Insertion sort for median */
	for (i = 1; i < n; i++) {
		__u64 key = buf[i];

		j = i - 1;
		while (j >= 0 && buf[j] > key) {
			buf[j + 1] = buf[j];
			j--;
		}
		buf[j + 1] = key;
	}

	return buf[n / 2];
}

static __u32 compute_batch_iters(__u64 per_op_ns)
{
	__u64 target_ns = (__u64)CALIBRATE_TARGET_MS * 1000000ULL;
	__u32 iters;

	if (per_op_ns == 0)
		return CALIBRATE_MIN_BATCH;

	iters = target_ns / per_op_ns;

	if (iters < CALIBRATE_MIN_BATCH)
		iters = CALIBRATE_MIN_BATCH;
	if (iters > CALIBRATE_MAX_BATCH)
		iters = CALIBRATE_MAX_BATCH;

	return iters;
}

void bpf_bench_calibrate(struct bpf_bench_timing *t,
			 bpf_bench_run_fn run_fn, void *run_ctx)
{
	__u64 elapsed, per_op_ns;
	__u64 time_n, time_2n;
	double ratio;

	elapsed = measure_elapsed(t, run_fn, run_ctx, CALIBRATE_SEED_BATCH, CALIBRATE_RUNS);
	if (elapsed == 0) {
		fprintf(stderr, "calibration: no timing samples, using default\n");
		t->batch_iters = 10000;
		*t->batch_iters_bss = t->batch_iters;
		reset_timing(t);
		return;
	}

	per_op_ns = elapsed / CALIBRATE_SEED_BATCH;
	t->batch_iters = compute_batch_iters(per_op_ns);

	printf("Calibration: %llu ns/op, batch_iters=%u (~%ums/batch)\n",
	       (unsigned long long)per_op_ns, t->batch_iters,
	       (unsigned int)(per_op_ns * t->batch_iters / 1000000));

	/* Proportionality check: 2N iterations should take 2x the time of N */
	time_n = measure_elapsed(t, run_fn, run_ctx, t->batch_iters, CALIBRATE_RUNS);
	time_2n = measure_elapsed(t, run_fn, run_ctx, t->batch_iters * 2, CALIBRATE_RUNS);

	if (time_n > 0 && time_2n > 0) {
		ratio = (double)time_2n / (double)time_n;

		if (fabs(ratio - 2.0) / 2.0 > PROPORTIONALITY_TOL)
			fprintf(stderr,
				"WARNING: proportionality check failed "
				"(2N/N ratio=%.3f, expected=2.000, error=%.1f%%)\n"
				"  System noise may be affecting results.\n",
				ratio, fabs(ratio - 2.0) / 2.0 * 100.0);
		else
			printf("Proportionality check: 2N/N ratio=%.4f (ok)\n",
			       ratio);
	}

	*t->batch_iters_bss = t->batch_iters;
	reset_timing(t);
}
