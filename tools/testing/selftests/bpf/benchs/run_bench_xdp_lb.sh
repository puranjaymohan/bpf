#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

# batch_iters is auto-calibrated to target ~10ms per batch.
WARMUP=${WARMUP:-3}

RUN="sudo ./bench -w${WARMUP} -a xdp-lb"

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
	printf "$HDR" "$1" "n" "p50" "stddev" "CV" "min" "p90" "p99" "max"
	printf "%s\n" "$SEP"
}

function run_scenario()
{
	local sc="$1"
	shift
	local result samples med sd c min_v p90 p99 max_v

	result=$($RUN --scenario "$sc" "$@" 2>&1)

	samples=$(grab '.*timing: ([0-9]+) samples.*' "$result")
	med=$(grab '.*median ([0-9]+\.[0-9]+) ns/op.*' "$result")
	sd=$(grab '.*stddev ([0-9]+\.[0-9]+),.*' "$result")
	c=$(grab '.*CV ([0-9]+\.[0-9]+%).*' "$result")
	min_v=$(grab '.*min ([0-9]+\.[0-9]+),.*' "$result")
	max_v=$(grab '.*max ([0-9]+\.[0-9]+)].*' "$result")
	p90=$(grab '.*p90 ([0-9]+\.[0-9]+),.*' "$result")
	p99=$(grab '.*p99 ([0-9]+\.[0-9]+)' "$result")

	printf "$ROW" "$sc" "$samples" "$med" "$sd" "$c" \
		"$min_v" "$p90" "$p99" "$max_v"
}

header "XDP load-balancer benchmark (auto-calibrated)"

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

group_header "TCP flags"
run_scenario tcp-v4-syn
run_scenario tcp-v4-rst-miss

group_header "LRU stress"
run_scenario tcp-v4-lru-miss
run_scenario udp-v4-lru-miss
run_scenario tcp-v4-lru-warmup

group_header "Early exits"
for sc in pass-v4-no-vip pass-v6-no-vip pass-v4-icmp pass-non-ip \
	  drop-v4-frag drop-v4-options drop-v6-frag; do
	run_scenario "$sc"
done
printf "%s\n" "$SEP"
