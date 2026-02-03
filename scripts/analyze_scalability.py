#!/usr/bin/env python3
"""
MeshChain Scalability Analysis
실제 시뮬레이션 로그에서 scalability 메트릭 추출
"""

import re
import json
from collections import defaultdict, Counter
from pathlib import Path
import statistics

def parse_scalability_log(log_file='scalability_600s.log'):
    """Parse simulation log and extract scalability metrics"""

    metrics = {
        'vehicles': {
            'total_spawned': set(),
            'active_per_second': defaultdict(int),
        },
        'blocks': {
            'total_attempts': 0,
            'successful': 0,
            'failed': 0,
            'diversity_failed': 0,
            'latencies': [],
        },
        'mesh': {
            'wave_neighbors': [],
            'max_neighbors': 0,
            'neighbor_distribution': Counter(),
        },
        'consensus': {
            'tof_verified': [],
            'witness_selected': [],
            'diversity_checks': {'passed': 0, 'failed': 0},
        },
        'failures': {
            'diversity_failed': [],
            'insufficient_witnesses': 0,
        }
    }

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            current_time = 0

            for line in f:
                # Extract vehicle IDs
                vehicle_match = re.search(r'\[([\w\._\-]+)\]', line)
                if vehicle_match and 'flow_route' in vehicle_match.group(1):
                    vehicle_id = vehicle_match.group(1)
                    metrics['vehicles']['total_spawned'].add(vehicle_id)

                # Extract simulation time
                time_match = re.search(r't=(\d+\.\d+)', line)
                if time_match:
                    current_time = int(float(time_match.group(1)))

                # Block creation attempts
                if 'V2X data received → Creating block' in line:
                    metrics['blocks']['total_attempts'] += 1

                # Block success/failure
                if 'Block creation: SUCCESS' in line:
                    metrics['blocks']['successful'] += 1
                    latency_match = re.search(r'\((\d+\.\d+)ms\)', line)
                    if latency_match:
                        metrics['blocks']['latencies'].append(float(latency_match.group(1)))

                if 'Block creation:' in line and 'FAILED' in line:
                    metrics['blocks']['failed'] += 1

                if 'DIVERSITY_FAILED' in line:
                    metrics['blocks']['diversity_failed'] += 1
                    if vehicle_match:
                        metrics['failures']['diversity_failed'].append(vehicle_match.group(1))

                # WAVE neighbors (mesh size)
                wave_match = re.search(r'WAVE_neighbors=(\d+)', line)
                if wave_match:
                    neighbors = int(wave_match.group(1))
                    metrics['mesh']['wave_neighbors'].append(neighbors)
                    metrics['mesh']['max_neighbors'] = max(metrics['mesh']['max_neighbors'], neighbors)
                    metrics['mesh']['neighbor_distribution'][neighbors] += 1

                # ToF verification
                tof_match = re.search(r'ToF verified: (\d+) / (\d+) required', line)
                if tof_match:
                    verified = int(tof_match.group(1))
                    metrics['consensus']['tof_verified'].append(verified)

                # Witness selection
                witness_match = re.search(r'Selected (\d+) witnesses', line)
                if witness_match:
                    selected = int(witness_match.group(1))
                    metrics['consensus']['witness_selected'].append(selected)

                # Diversity checks
                if 'Diversity check passed' in line:
                    metrics['consensus']['diversity_checks']['passed'] += 1
                if 'diversity check failed' in line:
                    metrics['consensus']['diversity_checks']['failed'] += 1

    except FileNotFoundError:
        print(f"Warning: {log_file} not found yet (simulation may still be starting)")
        return None

    return metrics

def compute_statistics(metrics):
    """Compute statistical summaries"""

    if not metrics:
        return None

    stats = {}

    # Vehicle stats
    stats['vehicles'] = {
        'total_unique': len(metrics['vehicles']['total_spawned']),
    }

    # Block stats
    total_blocks = metrics['blocks']['total_attempts']
    stats['blocks'] = {
        'total_attempts': total_blocks,
        'successful': metrics['blocks']['successful'],
        'failed': metrics['blocks']['failed'],
        'success_rate': (metrics['blocks']['successful'] / total_blocks * 100) if total_blocks > 0 else 0,
        'diversity_failure_rate': (metrics['blocks']['diversity_failed'] / total_blocks * 100) if total_blocks > 0 else 0,
    }

    if metrics['blocks']['latencies']:
        stats['blocks']['latency'] = {
            'min': min(metrics['blocks']['latencies']),
            'max': max(metrics['blocks']['latencies']),
            'mean': statistics.mean(metrics['blocks']['latencies']),
            'median': statistics.median(metrics['blocks']['latencies']),
            'p95': statistics.quantiles(metrics['blocks']['latencies'], n=20)[18] if len(metrics['blocks']['latencies']) > 20 else max(metrics['blocks']['latencies']),
        }

    # Mesh stats
    if metrics['mesh']['wave_neighbors']:
        stats['mesh'] = {
            'max_neighbors': metrics['mesh']['max_neighbors'],
            'mean_neighbors': statistics.mean(metrics['mesh']['wave_neighbors']),
            'median_neighbors': statistics.median(metrics['mesh']['wave_neighbors']),
            'distribution': dict(sorted(metrics['mesh']['neighbor_distribution'].items())),
        }

    # Consensus stats
    if metrics['consensus']['tof_verified']:
        stats['consensus'] = {
            'mean_tof_verified': statistics.mean(metrics['consensus']['tof_verified']),
            'mean_witnesses': statistics.mean(metrics['consensus']['witness_selected']) if metrics['consensus']['witness_selected'] else 0,
            'diversity_pass_rate': (metrics['consensus']['diversity_checks']['passed'] /
                                   (metrics['consensus']['diversity_checks']['passed'] +
                                    metrics['consensus']['diversity_checks']['failed']) * 100)
                                   if (metrics['consensus']['diversity_checks']['passed'] +
                                       metrics['consensus']['diversity_checks']['failed']) > 0 else 0,
        }

    return stats

def generate_report(stats, output_file='scalability_report.txt'):
    """Generate human-readable report"""

    if not stats:
        print("No statistics available yet")
        return

    with open(output_file, 'w') as f:
        f.write("="*70 + "\n")
        f.write("  MESHCHAIN SCALABILITY TEST REPORT\n")
        f.write("="*70 + "\n\n")

        # Vehicles
        f.write("--- Vehicle Scalability ---\n")
        f.write(f"  Total unique vehicles: {stats['vehicles']['total_unique']}\n")
        f.write(f"  Target: 200-300 vehicles\n")
        f.write(f"  Status: {'✓ ACHIEVED' if stats['vehicles']['total_unique'] >= 200 else '⚠ BELOW TARGET'}\n\n")

        # Blocks
        f.write("--- Block Creation Performance ---\n")
        f.write(f"  Total attempts: {stats['blocks']['total_attempts']}\n")
        f.write(f"  Successful: {stats['blocks']['successful']}\n")
        f.write(f"  Failed: {stats['blocks']['failed']}\n")
        f.write(f"  Success rate: {stats['blocks']['success_rate']:.2f}%\n")
        f.write(f"  Diversity failure rate: {stats['blocks']['diversity_failure_rate']:.2f}%\n\n")

        if 'latency' in stats['blocks']:
            f.write("--- Block Finality Latency ---\n")
            f.write(f"  Min: {stats['blocks']['latency']['min']:.2f} ms\n")
            f.write(f"  Mean: {stats['blocks']['latency']['mean']:.2f} ms\n")
            f.write(f"  Median: {stats['blocks']['latency']['median']:.2f} ms\n")
            f.write(f"  95th percentile: {stats['blocks']['latency']['p95']:.2f} ms\n")
            f.write(f"  Max: {stats['blocks']['latency']['max']:.2f} ms\n")
            f.write(f"  Target: < 100ms\n")
            f.write(f"  Status: {'✓ ACHIEVED' if stats['blocks']['latency']['p95'] < 100 else '⚠ EXCEEDED'}\n\n")

        # Mesh
        if 'mesh' in stats:
            f.write("--- Local Mesh Connectivity ---\n")
            f.write(f"  Max simultaneous neighbors: {stats['mesh']['max_neighbors']}\n")
            f.write(f"  Mean neighbors: {stats['mesh']['mean_neighbors']:.2f}\n")
            f.write(f"  Median neighbors: {stats['mesh']['median_neighbors']:.2f}\n")
            f.write(f"  Distribution:\n")
            for neighbors, count in stats['mesh']['distribution'].items():
                f.write(f"    {neighbors} neighbors: {count} times\n")
            f.write("\n")

        # Consensus
        if 'consensus' in stats:
            f.write("--- Consensus Performance ---\n")
            f.write(f"  Mean ToF verified: {stats['consensus']['mean_tof_verified']:.2f}\n")
            f.write(f"  Mean witnesses selected: {stats['consensus']['mean_witnesses']:.2f}\n")
            f.write(f"  Diversity pass rate: {stats['consensus']['diversity_pass_rate']:.2f}%\n\n")

        f.write("="*70 + "\n")

    print(f"✓ Report generated: {output_file}")

def export_json(stats, output_file='scalability_metrics.json'):
    """Export metrics as JSON"""
    if stats:
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"✓ JSON metrics exported: {output_file}")

def main():
    """Main analysis function"""
    print("\n" + "="*70)
    print("  MeshChain Scalability Analysis")
    print("="*70 + "\n")

    print("Parsing simulation log...")
    metrics = parse_scalability_log()

    if not metrics:
        print("⚠ No data available yet (simulation may still be starting)")
        return

    print("Computing statistics...")
    stats = compute_statistics(metrics)

    if not stats:
        print("⚠ Insufficient data for analysis")
        return

    print("\nGenerating reports...")
    generate_report(stats)
    export_json(stats)

    print("\n" + "="*70)
    print("  Summary")
    print("="*70)
    print(f"  Vehicles: {stats['vehicles']['total_unique']}")
    print(f"  Blocks: {stats['blocks']['successful']}/{stats['blocks']['total_attempts']} ({stats['blocks']['success_rate']:.1f}%)")
    if 'mesh' in stats:
        print(f"  Max mesh size: {stats['mesh']['max_neighbors']} neighbors")
    if 'latency' in stats.get('blocks', {}):
        print(f"  Latency (p95): {stats['blocks']['latency']['p95']:.2f} ms")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
