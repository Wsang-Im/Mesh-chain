#!/usr/bin/env python3
"""
Analyze RSU Anchoring Performance from 600s scalability test
"""

import re
import json
from collections import defaultdict
import statistics

def parse_anchoring_logs(log_file):
    """Parse anchoring data from log file"""

    rsu_anchors = defaultdict(list)  # RSU -> list of (anchor_id, blocks)
    total_anchors = 0
    anchor_blocks = []

    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        current_rsu = None

        for line in f:
            # Extract RSU name
            rsu_match = re.search(r'\[RSU-(RSU-\d+-[A-Z0-9-]+)\]', line)
            if rsu_match:
                current_rsu = rsu_match.group(1)

            # Extract anchor creation
            anchor_match = re.search(r'⚓ L1 Anchor #(\d+) created: (\d+) blocks', line)
            if anchor_match and current_rsu:
                anchor_id = int(anchor_match.group(1))
                blocks = int(anchor_match.group(2))

                rsu_anchors[current_rsu].append((anchor_id, blocks))
                anchor_blocks.append(blocks)
                total_anchors += 1

    return rsu_anchors, anchor_blocks, total_anchors

def analyze_anchoring(rsu_anchors, anchor_blocks, total_anchors):
    """Analyze anchoring performance"""

    # Overall statistics
    total_blocks_anchored = sum(anchor_blocks)
    mean_blocks = statistics.mean(anchor_blocks) if anchor_blocks else 0
    median_blocks = statistics.median(anchor_blocks) if anchor_blocks else 0
    min_blocks = min(anchor_blocks) if anchor_blocks else 0
    max_blocks = max(anchor_blocks) if anchor_blocks else 0
    stdev_blocks = statistics.stdev(anchor_blocks) if len(anchor_blocks) > 1 else 0

    # Per-RSU statistics
    rsu_stats = []
    for rsu, anchors in sorted(rsu_anchors.items()):
        blocks_list = [blocks for _, blocks in anchors]
        rsu_stats.append({
            'rsu': rsu,
            'anchor_count': len(anchors),
            'total_blocks': sum(blocks_list),
            'mean_blocks': statistics.mean(blocks_list) if blocks_list else 0,
            'min_blocks': min(blocks_list) if blocks_list else 0,
            'max_blocks': max(blocks_list) if blocks_list else 0
        })

    # 600s test = 10 periods (60s each)
    expected_anchors_per_rsu = 10
    num_rsus = len(rsu_anchors)

    return {
        'total_anchors': total_anchors,
        'total_blocks_anchored': total_blocks_anchored,
        'mean_blocks_per_anchor': mean_blocks,
        'median_blocks_per_anchor': median_blocks,
        'min_blocks_per_anchor': min_blocks,
        'max_blocks_per_anchor': max_blocks,
        'stdev_blocks_per_anchor': stdev_blocks,
        'num_rsus': num_rsus,
        'expected_anchors_per_rsu': expected_anchors_per_rsu,
        'rsu_stats': rsu_stats,
        'anchor_blocks_distribution': anchor_blocks
    }

def generate_report(stats, output_file='anchoring_report.txt'):
    """Generate text report"""

    with open(output_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("  MESHCHAIN RSU ANCHORING PERFORMANCE REPORT (600s Test)\n")
        f.write("=" * 70 + "\n\n")

        f.write("--- Overall Anchoring Performance ---\n")
        f.write(f"  Total L1 Anchors Created: {stats['total_anchors']}\n")
        f.write(f"  Total Blocks Anchored: {stats['total_blocks_anchored']}\n")
        f.write(f"  Anchor Period: 60s\n")
        f.write(f"  Test Duration: 600s\n")
        f.write(f"  Number of RSUs: {stats['num_rsus']}\n\n")

        f.write("--- Blocks per Anchor Statistics ---\n")
        f.write(f"  Mean: {stats['mean_blocks_per_anchor']:.1f} blocks\n")
        f.write(f"  Median: {stats['median_blocks_per_anchor']:.1f} blocks\n")
        f.write(f"  Min: {stats['min_blocks_per_anchor']} blocks\n")
        f.write(f"  Max: {stats['max_blocks_per_anchor']} blocks\n")
        f.write(f"  Std Dev: {stats['stdev_blocks_per_anchor']:.1f} blocks\n\n")

        f.write("--- Per-RSU Anchoring Performance ---\n")
        f.write(f"{'RSU':<25} {'Anchors':<10} {'Total Blocks':<15} {'Avg Blocks/Anchor':<20}\n")
        f.write("-" * 70 + "\n")

        for rsu_stat in stats['rsu_stats']:
            f.write(f"{rsu_stat['rsu']:<25} "
                   f"{rsu_stat['anchor_count']:<10} "
                   f"{rsu_stat['total_blocks']:<15} "
                   f"{rsu_stat['mean_blocks']:<20.1f}\n")

        f.write("\n--- Anchor Efficiency ---\n")
        anchors_per_rsu = [r['anchor_count'] for r in stats['rsu_stats']]
        f.write(f"  Expected anchors per RSU: {stats['expected_anchors_per_rsu']} (600s / 60s period)\n")
        f.write(f"  Actual anchors per RSU: {statistics.mean(anchors_per_rsu):.1f} (avg)\n")
        f.write(f"  Anchor creation rate: {(statistics.mean(anchors_per_rsu) / stats['expected_anchors_per_rsu'] * 100):.1f}%\n")

        f.write("\n" + "=" * 70 + "\n")

    print(f"✓ Anchoring report saved to: {output_file}")

def export_json(stats, output_file='anchoring_metrics.json'):
    """Export metrics to JSON"""

    output = {
        'test_duration_s': 600,
        'anchor_period_s': 60,
        'total_anchors': stats['total_anchors'],
        'total_blocks_anchored': stats['total_blocks_anchored'],
        'num_rsus': stats['num_rsus'],
        'blocks_per_anchor': {
            'mean': round(stats['mean_blocks_per_anchor'], 2),
            'median': round(stats['median_blocks_per_anchor'], 2),
            'min': stats['min_blocks_per_anchor'],
            'max': stats['max_blocks_per_anchor'],
            'stdev': round(stats['stdev_blocks_per_anchor'], 2)
        },
        'rsu_performance': stats['rsu_stats']
    }

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"✓ Anchoring metrics exported to: {output_file}")

def main():
    log_file = 'scalability_600s.log'

    print("=" * 60)
    print("  Analyzing RSU Anchoring Performance")
    print("=" * 60)
    print()

    print(f"Parsing anchoring logs from: {log_file}")
    rsu_anchors, anchor_blocks, total_anchors = parse_anchoring_logs(log_file)

    print(f"✓ Found {total_anchors} L1 anchors from {len(rsu_anchors)} RSUs")
    print()

    print("Analyzing anchoring performance...")
    stats = analyze_anchoring(rsu_anchors, anchor_blocks, total_anchors)

    print()
    print("Generating reports...")
    generate_report(stats, 'anchoring_report.txt')
    export_json(stats, 'anchoring_metrics.json')

    print()
    print("=" * 60)
    print("✓ Anchoring analysis completed!")
    print("=" * 60)
    print()

    # Print summary
    print("Summary Statistics:")
    print(f"  Total Anchors: {stats['total_anchors']}")
    print(f"  Total Blocks Anchored: {stats['total_blocks_anchored']}")
    print(f"  Avg Blocks per Anchor: {stats['mean_blocks_per_anchor']:.1f}")
    print(f"  Anchor Period: 60s")
    print(f"  Number of RSUs: {stats['num_rsus']}")
    print()

if __name__ == '__main__':
    main()
