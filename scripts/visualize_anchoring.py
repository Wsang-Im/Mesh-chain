#!/usr/bin/env python3
"""
Visualize RSU Anchoring Performance for Paper
"""

import json
import matplotlib.pyplot as plt
import matplotlib
import numpy as np

# Use non-interactive backend
matplotlib.use('Agg')

def load_data(json_file='anchoring_metrics.json'):
    """Load anchoring metrics from JSON"""
    with open(json_file, 'r') as f:
        return json.load(f)

def generate_latex_table(data, output_file='paper_figures/anchoring_table.tex'):
    """Generate LaTeX table for paper"""

    with open(output_file, 'w') as f:
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{RSU Anchoring Performance (600s Test, 60s Period)}\n")
        f.write("\\label{tab:anchoring}\n")
        f.write("\\begin{tabular}{lr}\n")
        f.write("\\toprule\n")
        f.write("Metric & Value \\\\\n")
        f.write("\\midrule\n")

        f.write(f"Total L1 Anchors Created & {data['total_anchors']} \\\\\n")
        f.write(f"Total Blocks Anchored & {data['total_blocks_anchored']:,} \\\\\n")
        f.write(f"Number of RSUs & {data['num_rsus']} \\\\\n")
        f.write(f"Anchor Period & 60 s \\\\\n")
        f.write(f"Avg Blocks per Anchor & {data['blocks_per_anchor']['mean']:.1f} \\\\\n")
        f.write(f"Median Blocks per Anchor & {data['blocks_per_anchor']['median']:.1f} \\\\\n")
        f.write(f"Min Blocks per Anchor & {data['blocks_per_anchor']['min']} \\\\\n")
        f.write(f"Max Blocks per Anchor & {data['blocks_per_anchor']['max']} \\\\\n")
        f.write(f"Anchoring Efficiency & 90.0\\% \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"✓ Saved: {output_file}")

def plot_blocks_per_anchor_distribution(data, output_file='paper_figures/fig9_anchoring_distribution.pdf'):
    """Plot distribution of blocks per anchor"""

    # Get all anchor blocks data
    rsu_data = data['rsu_performance']

    # Extract data for each RSU
    rsu_names = []
    avg_blocks = []

    for rsu in rsu_data:
        # Shorten RSU names for readability
        short_name = rsu['rsu'].replace('RSU-', 'R').replace('-FM-', '-').replace('-MAIN-', '-M-')
        rsu_names.append(short_name)
        avg_blocks.append(rsu['mean_blocks'])

    fig, ax = plt.subplots(figsize=(10, 5))

    bars = ax.bar(range(len(rsu_names)), avg_blocks, color='steelblue', alpha=0.8, edgecolor='black')

    # Add mean line
    mean_val = data['blocks_per_anchor']['mean']
    ax.axhline(y=mean_val, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_val:.1f}')

    ax.set_xlabel('RSU', fontsize=12, fontweight='bold')
    ax.set_ylabel('Avg Blocks per Anchor', fontsize=12, fontweight='bold')
    ax.set_title('RSU Anchoring Performance (600s Test)', fontsize=14, fontweight='bold')
    ax.set_xticks(range(len(rsu_names)))
    ax.set_xticklabels(rsu_names, rotation=45, ha='right', fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    ax.legend(fontsize=10)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"✓ Saved: {output_file}")

def plot_anchoring_summary(data, output_file='paper_figures/fig10_anchoring_summary.pdf'):
    """Plot anchoring summary statistics"""

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 8))

    # Panel 1: Total anchors created
    ax1.bar(['Total Anchors'], [data['total_anchors']], color='forestgreen', alpha=0.8, edgecolor='black')
    ax1.set_ylabel('Count', fontsize=11, fontweight='bold')
    ax1.set_title('(a) Total L1 Anchors Created', fontsize=12, fontweight='bold')
    ax1.text(0, data['total_anchors'] + 5, f"{data['total_anchors']}",
             ha='center', va='bottom', fontsize=14, fontweight='bold')
    ax1.set_ylim([0, data['total_anchors'] * 1.15])
    ax1.grid(axis='y', alpha=0.3)

    # Panel 2: Total blocks anchored
    ax2.bar(['Total Blocks'], [data['total_blocks_anchored']], color='darkorange', alpha=0.8, edgecolor='black')
    ax2.set_ylabel('Blocks', fontsize=11, fontweight='bold')
    ax2.set_title('(b) Total Blocks Anchored', fontsize=12, fontweight='bold')
    ax2.text(0, data['total_blocks_anchored'] + 300, f"{data['total_blocks_anchored']:,}",
             ha='center', va='bottom', fontsize=14, fontweight='bold')
    ax2.set_ylim([0, data['total_blocks_anchored'] * 1.15])
    ax2.grid(axis='y', alpha=0.3)

    # Panel 3: Blocks per anchor statistics
    stats = data['blocks_per_anchor']
    labels = ['Mean', 'Median', 'Min', 'Max']
    values = [stats['mean'], stats['median'], stats['min'], stats['max']]
    colors = ['steelblue', 'teal', 'crimson', 'purple']

    bars = ax3.bar(labels, values, color=colors, alpha=0.8, edgecolor='black')
    ax3.set_ylabel('Blocks', fontsize=11, fontweight='bold')
    ax3.set_title('(c) Blocks per Anchor Statistics', fontsize=12, fontweight='bold')
    ax3.grid(axis='y', alpha=0.3)

    for bar, val in zip(bars, values):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 3,
                f'{val:.0f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

    # Panel 4: Anchoring efficiency
    efficiency = 90.0  # From report
    ax4.bar(['Efficiency'], [efficiency], color='gold', alpha=0.8, edgecolor='black')
    ax4.set_ylabel('Percentage (%)', fontsize=11, fontweight='bold')
    ax4.set_title('(d) Anchoring Efficiency (600s)', fontsize=12, fontweight='bold')
    ax4.set_ylim([0, 100])
    ax4.axhline(y=100, color='green', linestyle='--', linewidth=1.5, alpha=0.5, label='Target: 100%')
    ax4.text(0, efficiency + 3, f"{efficiency:.1f}%",
             ha='center', va='bottom', fontsize=14, fontweight='bold')
    ax4.grid(axis='y', alpha=0.3)
    ax4.legend(fontsize=9)

    plt.suptitle('MeshChain RSU Anchoring Performance', fontsize=16, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"✓ Saved: {output_file}")

def main():
    print("=" * 60)
    print("  MeshChain Anchoring Visualization")
    print("  Generating paper-ready figures...")
    print("=" * 60)
    print()

    # Load data
    data = load_data('anchoring_metrics.json')
    print(f"✓ Loaded anchoring metrics")
    print()

    print("Generating figures...")
    print()

    # Generate figures
    plot_blocks_per_anchor_distribution(data)
    plot_anchoring_summary(data)

    # Generate LaTeX table
    generate_latex_table(data)

    print()
    print("=" * 60)
    print("✓ All anchoring figures generated successfully!")
    print("  Output directory: paper_figures/")
    print("=" * 60)
    print()

    # Print summary
    print("Summary Statistics:")
    print(f"  Total Anchors: {data['total_anchors']}")
    print(f"  Total Blocks Anchored: {data['total_blocks_anchored']:,}")
    print(f"  Avg Blocks per Anchor: {data['blocks_per_anchor']['mean']:.1f}")
    print(f"  Anchoring Efficiency: 90.0%")
    print()

if __name__ == '__main__':
    main()
