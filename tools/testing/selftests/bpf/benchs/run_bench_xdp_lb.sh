#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

# batch_iters=100K: best signal-to-noise trade-off.
#   - ktime_get_ns() bias: 50 ns / 100K = 0.0005 ns/op (negligible)
#   - ~600-4096 samples per scenario in 5s (enough for robust stats)
#   - CV < 0.2% for full-pipeline scenarios
# Higher values (1M) give fewer samples (62-101 in 5s) without
# improving the mean; lower values (10K) are fine too but noisier.
BATCH=${BATCH_ITERS:-100000}
WARMUP=${WARMUP:-3}
DURATION=${DURATION:-5}

RUN="sudo ./bench -w${WARMUP} -d${DURATION} -a xdp-lb --batch-iters ${BATCH}"

function grab()
{
	local pat="$1"
	shift
	echo "$*" | sed -nE "s|$pat|\1|p"
}

SEP="  +----------------------------------+------+----------+---------+--------+----------+----------+----------+----------+"
HDR="  | %-32s | %4s | %8s | %7s | %6s | %8s | %8s | %8s | %8s |\n"
ROW="  | %-32s | %4s | %8s | %7s | %6s | %8s | %8s | %8s | %8s |\n"

function group_header()
{
	printf "%s\n" "$SEP"
	printf "$HDR" "$1" "n" "ns/op" "stddev" "CV" "min" "median" "p99" "max"
	printf "%s\n" "$SEP"
}

function run_scenario()
{
	local sc="$1"
	shift
	local result samples avg sd c min_v med p99 max_v

	result=$($RUN --scenario "$sc" "$@" 2>&1)

	samples=$(grab '.*timing: ([0-9]+) batch samples.*' "$result")
	avg=$(grab '.*avg ([0-9]+\.[0-9]+) ns/op.*' "$result")
	sd=$(grab '.*stddev ([0-9]+\.[0-9]+) ns.*' "$result")
	c=$(grab '.*CV ([0-9]+\.[0-9]+%).*' "$result")

	local pline
	pline=$(echo "$result" | grep "min ")
	min_v=$(grab '.*min ([0-9]+\.[0-9]+),.*' "$pline")
	med=$(grab '.*median ([0-9]+\.[0-9]+),.*' "$pline")
	p99=$(grab '.*p99 ([0-9]+\.[0-9]+),.*' "$pline")
	max_v=$(grab '.*max ([0-9]+\.[0-9]+) ns.*' "$pline")

	printf "$ROW" "$sc" "$samples" "$avg" "$sd" "$c" \
		"$min_v" "$med" "$p99" "$max_v"
}

header "XDP load-balancer benchmark (batch_iters=$BATCH)"

group_header "Single-flow baseline"
for sc in tcp-v4-lru-hit tcp-v4-ch \
	  tcp-v6-lru-hit tcp-v6-ch \
	  udp-v4-lru-hit udp-v6-lru-hit \
	  tcp-v4v6-lru-hit; do
	run_scenario "$sc"
done

group_header "Diverse flows (4K src addrs)"
for sc in tcp-v4-lru-diverse tcp-v4-ch-diverse \
	  tcp-v6-lru-diverse tcp-v6-ch-diverse \
	  udp-v4-lru-diverse; do
	run_scenario "$sc"
done

group_header "LRU stress"
run_scenario tcp-v4-lru-miss
run_scenario udp-v4-lru-miss
run_scenario tcp-v4-lru-warmup --batch-iters 6500

group_header "Early exits"
for sc in pass-v4-no-vip pass-non-ip drop-v4-frag; do
	run_scenario "$sc"
done
printf "%s\n" "$SEP"
