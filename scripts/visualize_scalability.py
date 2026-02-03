#!/usr/bin/env python3
"""
MeshChain Scalability Visualization
Scalability 테스트 결과 가시화
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Set style
plt.style.use('seaborn-v0_8-paper')
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 12  # Increased from 10 for better readability

output_dir = Path('paper_figures')
output_dir.mkdir(exist_ok=True)

def load_metrics(json_file='scalability_metrics.json'):
    """Load metrics from JSON"""
    with open(json_file, 'r') as f:
        return json.load(f)

def plot_mesh_connectivity(stats):
    """
    Figure 6: Local Mesh Connectivity Distribution
    Shows how many neighbors each vehicle typically has
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Distribution bar chart
    if 'distribution' in stats['mesh']:
        neighbors = list(stats['mesh']['distribution'].keys())
        counts = list(stats['mesh']['distribution'].values())

        ax1.bar([int(n) for n in neighbors], counts, color='0.5', edgecolor='black', linewidth=1.5)
        ax1.set_xlabel('Number of WAVE Neighbors (Mesh Size)', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Frequency', fontsize=14, fontweight='bold')
        ax1.set_title('(a) Local Mesh Size Distribution', fontsize=16, fontweight='bold')
        ax1.tick_params(axis='both', which='major', labelsize=12)
        ax1.grid(axis='y', alpha=0.3)
        ax1.axvline(x=stats['mesh']['mean_neighbors'], color='black', linestyle='--',
                   linewidth=2.5, label=f'Mean: {stats['mesh']['mean_neighbors']:.1f}')
        ax1.legend(fontsize=14, loc='upper right')

    # Summary statistics
    max_n = stats['mesh']['max_neighbors']
    mean_n = stats['mesh']['mean_neighbors']
    median_n = stats['mesh']['median_neighbors']

    categories = ['Max', 'Mean', 'Median']
    values = [max_n, mean_n, median_n]
    colors = ['0.3', '0.5', '0.7']  # Grayscale

    ax2.barh(categories, values, color=colors, edgecolor='black', linewidth=1.5)
    ax2.set_xlabel('Number of Neighbors', fontsize=14, fontweight='bold')
    ax2.set_title('(b) Mesh Connectivity Summary', fontsize=16, fontweight='bold')
    ax2.tick_params(axis='both', which='major', labelsize=12)
    ax2.grid(axis='x', alpha=0.3)

    # Remove value labels (as requested)

    plt.tight_layout()
    plt.savefig(output_dir / 'fig6_mesh_connectivity.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig6_mesh_connectivity.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig6_mesh_connectivity.pdf")
    plt.close()

def plot_latency_performance(stats):
    """
    Figure 7: Block Finality Latency
    Shows latency distribution and percentiles
    """
    if 'latency' not in stats['blocks']:
        print("⚠ No latency data available")
        return

    fig, ax1 = plt.subplots(1, 1, figsize=(8, 6))

    latency = stats['blocks']['latency']

    # Latency statistics
    metrics = ['Min', 'Mean', 'Median', 'P95', 'Max']
    values = [latency['min'], latency['mean'], latency['median'],
             latency['p95'], latency['max']]

    # Use grayscale colors
    colors = ['0.3', '0.4', '0.5', '0.6', '0.7']  # Different shades of gray
    ax1.bar(metrics, values, color=colors, edgecolor='black', linewidth=1.5)
    ax1.set_ylabel('Latency (ms)', fontsize=14, fontweight='bold')
    ax1.set_title('Block Finality Latency Statistics', fontsize=16, fontweight='bold')
    ax1.tick_params(axis='both', which='major', labelsize=12)
    ax1.axhline(y=100, color='black', linestyle='--', linewidth=2,
               alpha=0.7, label='Target: 100ms')
    ax1.legend(fontsize=12)
    ax1.grid(axis='y', alpha=0.3)

    # Add value labels
    for i, v in enumerate(values):
        ax1.text(i, v + 2, f'{v:.1f}', ha='center', fontsize=11, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_dir / 'fig7_latency_performance.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig7_latency_performance.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig7_latency_performance.pdf")
    plt.close()

def plot_scalability_summary(stats):
    """
    Figure 8: Scalability Test Summary
    Overall performance metrics
    """
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))

    # Vehicle count
    vehicle_count = stats['vehicles']['total_unique']
    ax1.bar(['Vehicles'], [vehicle_count], color='#3498db', alpha=0.8, edgecolor='black', width=0.5)
    ax1.axhline(y=200, color='g', linestyle='--', linewidth=1.5, alpha=0.5, label='Target Min: 200')
    ax1.set_ylabel('Count')
    ax1.set_title('(a) Total Vehicles')
    ax1.set_ylim(0, max(300, vehicle_count + 50))
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    ax1.text(0, vehicle_count + 10, f'{vehicle_count}', ha='center', fontweight='bold', fontsize=14)

    # Block success rate
    success_rate = stats['blocks']['success_rate']
    failure_rate = 100 - success_rate
    ax2.pie([success_rate, failure_rate],
           labels=['Success', 'Failed'],
           colors=['#2ecc71', '#e74c3c'],
           autopct='%1.1f%%',
           startangle=90,
           explode=(0.05, 0))
    ax2.set_title(f"(b) Block Creation Success Rate\n(Total: {stats['blocks']['total_attempts']})")

    # Mesh size
    max_mesh = stats['mesh']['max_neighbors']
    mean_mesh = stats['mesh']['mean_neighbors']
    ax3.bar(['Max Mesh Size', 'Mean Mesh Size'], [max_mesh, mean_mesh],
           color=['#e74c3c', '#3498db'], alpha=0.8, edgecolor='black')
    ax3.set_ylabel('Number of Neighbors')
    ax3.set_title('(c) Dynamic Mesh Formation')
    ax3.grid(axis='y', alpha=0.3)
    ax3.text(0, max_mesh + 0.3, f'{max_mesh}', ha='center', fontweight='bold', fontsize=12)
    ax3.text(1, mean_mesh + 0.3, f'{mean_mesh:.1f}', ha='center', fontweight='bold', fontsize=12)

    # Latency target achievement
    if 'latency' in stats['blocks']:
        p95 = stats['blocks']['latency']['p95']
        target = 100
        ax4.barh(['P95 Latency', 'Target'], [p95, target],
                color=['#2ecc71' if p95 < 100 else '#e74c3c', '#95a5a6'],
                alpha=0.8, edgecolor='black')
        ax4.set_xlabel('Latency (ms)')
        ax4.set_title('(d) Real-Time Performance (< 100ms)')
        ax4.grid(axis='x', alpha=0.3)
        ax4.text(p95 + 2, 0, f'{p95:.1f} ms', va='center', fontweight='bold')
        ax4.text(target + 2, 1, f'{target} ms', va='center', fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_dir / 'fig8_scalability_summary.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig8_scalability_summary.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig8_scalability_summary.pdf")
    plt.close()

def create_latex_scalability_table(stats, output_file='scalability_table.tex'):
    """Generate LaTeX table for scalability results"""
    with open(output_dir / output_file, 'w') as f:
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{MeshChain Scalability Performance (200+ Vehicles)}\n")
        f.write("\\label{tab:scalability}\n")
        f.write("\\begin{tabular}{lrr}\n")
        f.write("\\toprule\n")
        f.write("Metric & Value & Target \\\\\n")
        f.write("\\midrule\n")

        f.write(f"Total Vehicles & {stats['vehicles']['total_unique']} & 200-300 \\\\\n")
        f.write(f"Block Attempts & {stats['blocks']['total_attempts']} & - \\\\\n")
        f.write(f"Success Rate & {stats['blocks']['success_rate']:.1f}\\% & >70\\% \\\\\n")

        if 'latency' in stats['blocks']:
            f.write(f"Latency (Mean) & {stats['blocks']['latency']['mean']:.1f} ms & <100 ms \\\\\n")
            f.write(f"Latency (P95) & {stats['blocks']['latency']['p95']:.1f} ms & <100 ms \\\\\n")

        f.write(f"Max Mesh Size & {stats['mesh']['max_neighbors']} & - \\\\\n")
        f.write(f"Mean Mesh Size & {stats['mesh']['mean_neighbors']:.1f} & - \\\\\n")

        if 'consensus' in stats:
            f.write(f"Diversity Pass Rate & {stats['consensus']['diversity_pass_rate']:.1f}\\% & >80\\% \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"✓ Saved: {output_dir}/{output_file}")

def main():
    """Generate all scalability visualizations"""
    print("\n" + "="*70)
    print("  MeshChain Scalability Visualization")
    print("="*70 + "\n")

    try:
        stats = load_metrics()
        print(f"✓ Loaded metrics\n")
    except FileNotFoundError:
        print("Error: scalability_metrics.json not found!")
        print("Please run analyze_scalability.py first.\n")
        return

    print("Generating figures...\n")
    plot_mesh_connectivity(stats)
    plot_latency_performance(stats)
    plot_scalability_summary(stats)
    create_latex_scalability_table(stats)

    print("\n" + "="*70)
    print("✓ All scalability figures generated!")
    print(f"  Output directory: {output_dir}/")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
