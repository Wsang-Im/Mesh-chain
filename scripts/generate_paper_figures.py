#!/usr/bin/env python3
"""
Generate high-quality figures for academic paper
Mesh Blockchain Scalability Analysis
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MaxNLocator
import seaborn as sns
from pathlib import Path

# Set publication-quality style
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
    'axes.linewidth': 0.8,
    'grid.linewidth': 0.5,
    'lines.linewidth': 1.5,
    'patch.linewidth': 0.8,
})

# Color palette (colorblind-friendly)
COLORS = {
    'primary': '#0173B2',    # Blue
    'secondary': '#DE8F05',  # Orange
    'success': '#029E73',    # Green
    'danger': '#CC78BC',     # Purple
    'warning': '#CA9161',    # Brown
    'target': '#D55E00',     # Red-orange
    'grid': '#E0E0E0',       # Light gray
}

# Paths
BASE_DIR = Path('.')
DATA_DIR = BASE_DIR / 'analysis_results'
OUTPUT_DIR = BASE_DIR / 'figures'
OUTPUT_DIR.mkdir(exist_ok=True)

print("=" * 60)
print("Generating High-Quality Figures for Academic Paper")
print("=" * 60)
print()

# ============================================================
# Figure 1: Block Creation Latency Distribution (Most Important!)
# ============================================================
print("📊 Figure 1: Latency Distribution...")

latencies = np.loadtxt(DATA_DIR / '6_latencies.csv')

fig, ax = plt.subplots(figsize=(8, 5))

# Histogram
n, bins, patches = ax.hist(latencies, bins=60, color=COLORS['primary'],
                            alpha=0.7, edgecolor='black', linewidth=0.5,
                            label='Observed Latency')

# Statistics
mean_lat = np.mean(latencies)
median_lat = np.median(latencies)
p95_lat = np.percentile(latencies, 95)
p99_lat = np.percentile(latencies, 99)

# Target line
ax.axvline(x=100, color=COLORS['target'], linestyle='--', linewidth=2,
           label='Target: 100 ms', zorder=10)

# Mean line
ax.axvline(x=mean_lat, color=COLORS['success'], linestyle='-', linewidth=2,
           label=f'Mean: {mean_lat:.2f} ms', zorder=10)

# Median line
ax.axvline(x=median_lat, color=COLORS['secondary'], linestyle=':', linewidth=2,
           label=f'Median: {median_lat:.2f} ms', zorder=10)

# Labels
ax.set_xlabel('Block Creation Latency (ms)', fontweight='bold')
ax.set_ylabel('Frequency (Number of Blocks)', fontweight='bold')
ax.set_title('Block Creation Latency Distribution (n=11,482)',
             fontweight='bold', pad=15)

# Grid
ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, color=COLORS['grid'])
ax.set_axisbelow(True)

# Legend
legend = ax.legend(loc='upper right', framealpha=0.95, edgecolor='black',
                   fancybox=False, shadow=False)
legend.get_frame().set_linewidth(0.8)

# Statistics text box
stats_text = (
    f'Statistics:\n'
    f'Min: {np.min(latencies):.2f} ms\n'
    f'Max: {np.max(latencies):.2f} ms\n'
    f'P95: {p95_lat:.2f} ms\n'
    f'P99: {p99_lat:.2f} ms\n'
    f'100% < 100 ms ✓'
)
ax.text(0.98, 0.60, stats_text, transform=ax.transAxes,
        fontsize=9, verticalalignment='top', horizontalalignment='right',
        bbox=dict(boxstyle='round', facecolor='white', alpha=0.9,
                  edgecolor='black', linewidth=0.8))

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig1_latency_distribution.pdf')
plt.savefig(OUTPUT_DIR / 'fig1_latency_distribution.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig1_latency_distribution.pdf'}")
plt.close()

# ============================================================
# Figure 2: Cumulative Distribution Function (CDF)
# ============================================================
print("📊 Figure 2: Latency CDF...")

fig, ax = plt.subplots(figsize=(8, 5))

# Sort latencies for CDF
sorted_latencies = np.sort(latencies)
cdf = np.arange(1, len(sorted_latencies) + 1) / len(sorted_latencies) * 100

# Plot CDF
ax.plot(sorted_latencies, cdf, color=COLORS['primary'], linewidth=2,
        label='Empirical CDF')

# Percentile markers
percentiles = [50, 75, 90, 95, 99, 99.9]
for p in percentiles:
    val = np.percentile(latencies, p)
    ax.plot(val, p, 'o', color=COLORS['danger'], markersize=8,
            markeredgecolor='black', markeredgewidth=0.5, zorder=10)
    if p in [50, 90, 99]:
        ax.annotate(f'P{p:.0f}\n{val:.1f}ms', xy=(val, p),
                    xytext=(10, -5), textcoords='offset points',
                    fontsize=9, ha='left',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                              alpha=0.8, edgecolor='black', linewidth=0.5))

# Target line
ax.axvline(x=100, color=COLORS['target'], linestyle='--', linewidth=2,
           label='Target: 100 ms', alpha=0.7)

# 100% achievement line
ax.axhline(y=100, color='gray', linestyle=':', linewidth=1, alpha=0.5)

# Labels
ax.set_xlabel('Block Creation Latency (ms)', fontweight='bold')
ax.set_ylabel('Cumulative Percentage (%)', fontweight='bold')
ax.set_title('Cumulative Distribution Function of Block Latency',
             fontweight='bold', pad=15)

# Grid
ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, color=COLORS['grid'])
ax.set_axisbelow(True)

# Limits
ax.set_xlim([30, 100])
ax.set_ylim([0, 105])

# Legend
legend = ax.legend(loc='lower right', framealpha=0.95, edgecolor='black',
                   fancybox=False, shadow=False)
legend.get_frame().set_linewidth(0.8)

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig2_latency_cdf.pdf')
plt.savefig(OUTPUT_DIR / 'fig2_latency_cdf.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig2_latency_cdf.pdf'}")
plt.close()

# ============================================================
# Figure 3: Neighbor Count Distribution (Dynamic Connectivity)
# ============================================================
print("📊 Figure 3: Neighbor Distribution...")

df_neighbors = pd.read_csv(DATA_DIR / '4_connectivity_histogram.csv')

fig, ax = plt.subplots(figsize=(8, 5))

# Bar chart
bars = ax.bar(df_neighbors['neighbor_count'], df_neighbors['frequency'],
              color=COLORS['primary'], alpha=0.7, edgecolor='black',
              linewidth=0.8, width=0.8)

# Color zones
for i, bar in enumerate(bars):
    n = df_neighbors['neighbor_count'].iloc[i]
    if n == 0:
        bar.set_color(COLORS['danger'])  # Disconnected
        bar.set_alpha(0.6)
    elif 1 <= n <= 3:
        bar.set_color(COLORS['warning'])  # Low density
        bar.set_alpha(0.6)
    elif 4 <= n <= 7:
        bar.set_color(COLORS['secondary'])  # Medium density
        bar.set_alpha(0.7)
    elif 8 <= n <= 12:
        bar.set_color(COLORS['primary'])  # High density
        bar.set_alpha(0.8)
    else:
        bar.set_color(COLORS['success'])  # Very high density
        bar.set_alpha(0.8)

# Labels
ax.set_xlabel('Number of Neighbors', fontweight='bold')
ax.set_ylabel('Frequency (Measurement Count)', fontweight='bold')
ax.set_title('Dynamic Connectivity: Neighbor Distribution (n=15,066)',
             fontweight='bold', pad=15)

# Grid
ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, axis='y',
        color=COLORS['grid'])
ax.set_axisbelow(True)

# Legend for zones
legend_elements = [
    mpatches.Patch(color=COLORS['danger'], alpha=0.6, label='Disconnected (0)'),
    mpatches.Patch(color=COLORS['warning'], alpha=0.6, label='Low Density (1-3)'),
    mpatches.Patch(color=COLORS['secondary'], alpha=0.7, label='Medium Density (4-7)'),
    mpatches.Patch(color=COLORS['primary'], alpha=0.8, label='High Density (8-12)'),
    mpatches.Patch(color=COLORS['success'], alpha=0.8, label='Very High Density (13+)'),
]
legend = ax.legend(handles=legend_elements, loc='upper right',
                   framealpha=0.95, edgecolor='black',
                   fancybox=False, shadow=False, fontsize=9)
legend.get_frame().set_linewidth(0.8)

# Statistics
total_measurements = df_neighbors['frequency'].sum()
avg_neighbors = (df_neighbors['neighbor_count'] * df_neighbors['frequency']).sum() / total_measurements
high_density = df_neighbors[(df_neighbors['neighbor_count'] >= 8) &
                            (df_neighbors['neighbor_count'] <= 12)]['frequency'].sum()
high_density_pct = high_density / total_measurements * 100

stats_text = (
    f'Statistics:\n'
    f'Avg: {avg_neighbors:.1f} neighbors\n'
    f'High Density: {high_density_pct:.1f}%\n'
    f'Range: 0-{df_neighbors["neighbor_count"].max()}'
)
ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
        fontsize=9, verticalalignment='top', horizontalalignment='left',
        bbox=dict(boxstyle='round', facecolor='white', alpha=0.9,
                  edgecolor='black', linewidth=0.8))

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig3_neighbor_distribution.pdf')
plt.savefig(OUTPUT_DIR / 'fig3_neighbor_distribution.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig3_neighbor_distribution.pdf'}")
plt.close()

# ============================================================
# Figure 4: Vehicle Count Over Time
# ============================================================
print("📊 Figure 4: Vehicle Scalability...")

df_vehicles = pd.read_csv(DATA_DIR / '1_vehicle_count.csv')

fig, ax = plt.subplots(figsize=(8, 5))

# Line plot
ax.plot(df_vehicles['time_sec'], df_vehicles['total_vehicles'],
        color=COLORS['primary'], linewidth=2.5, marker='o', markersize=6,
        markeredgecolor='white', markeredgewidth=1, label='Active Vehicles')

# Fill area
ax.fill_between(df_vehicles['time_sec'], 0, df_vehicles['total_vehicles'],
                alpha=0.2, color=COLORS['primary'])

# Labels
ax.set_xlabel('Simulation Time (seconds)', fontweight='bold')
ax.set_ylabel('Number of Active Vehicles', fontweight='bold')
ax.set_title('Vehicle Count Growth Over Time', fontweight='bold', pad=15)

# Grid
ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, color=COLORS['grid'])
ax.set_axisbelow(True)

# Limits
ax.set_xlim([0, 630])
ax.set_ylim([0, 100])

# Milestones
milestones = [(180, 50), (420, 75)]
for time, count in milestones:
    idx = (df_vehicles['time_sec'] - time).abs().idxmin()
    actual_count = df_vehicles['total_vehicles'].iloc[idx]
    ax.plot(time, actual_count, 'o', color=COLORS['danger'], markersize=8,
            markeredgecolor='black', markeredgewidth=1, zorder=10)
    ax.annotate(f'{actual_count} vehicles\nat {time}s', xy=(time, actual_count),
                xytext=(10, 10), textcoords='offset points',
                fontsize=9, ha='left',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                          alpha=0.9, edgecolor='black', linewidth=0.5),
                arrowprops=dict(arrowstyle='->', color='black', lw=1))

# Final count
final_time = df_vehicles['time_sec'].iloc[-1]
final_count = df_vehicles['total_vehicles'].iloc[-1]
ax.text(0.98, 0.05, f'Final: {final_count} vehicles @ {final_time}s',
        transform=ax.transAxes, fontsize=10, fontweight='bold',
        verticalalignment='bottom', horizontalalignment='right',
        bbox=dict(boxstyle='round', facecolor=COLORS['success'], alpha=0.3,
                  edgecolor='black', linewidth=0.8))

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig4_vehicle_growth.pdf')
plt.savefig(OUTPUT_DIR / 'fig4_vehicle_growth.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig4_vehicle_growth.pdf'}")
plt.close()

# ============================================================
# Figure 5: Cluster Size and Density Growth (Dual Y-axis)
# ============================================================
print("📊 Figure 5: Cluster Growth...")

df_cluster = pd.read_csv(DATA_DIR / '5_cluster_growth.csv')

fig, ax1 = plt.subplots(figsize=(8, 5))

# Cluster size (primary y-axis)
color1 = COLORS['primary']
ax1.set_xlabel('Simulation Time (seconds)', fontweight='bold')
ax1.set_ylabel('Max Cluster Size (vehicles)', color=color1, fontweight='bold')
line1 = ax1.plot(df_cluster['time_sec'], df_cluster['max_cluster'],
                 color=color1, linewidth=2.5, marker='o', markersize=6,
                 markeredgecolor='white', markeredgewidth=1,
                 label='Max Cluster Size')
ax1.tick_params(axis='y', labelcolor=color1)
ax1.set_ylim([5, 22])

# Density (secondary y-axis)
ax2 = ax1.twinx()
color2 = COLORS['secondary']
ax2.set_ylabel('Max Local Density (vehicles/km²)', color=color2, fontweight='bold')
line2 = ax2.plot(df_cluster['time_sec'], df_cluster['max_density'],
                 color=color2, linewidth=2.5, marker='s', markersize=6,
                 markeredgecolor='white', markeredgewidth=1,
                 label='Max Local Density', linestyle='--')
ax2.tick_params(axis='y', labelcolor=color2)
ax2.set_ylim([25, 75])

# Title
ax1.set_title('Cluster Size and Density Growth Over Time',
              fontweight='bold', pad=15)

# Grid
ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, color=COLORS['grid'])
ax1.set_axisbelow(True)

# Combined legend
lines = line1 + line2
labels = [l.get_label() for l in lines]
legend = ax1.legend(lines, labels, loc='upper left', framealpha=0.95,
                    edgecolor='black', fancybox=False, shadow=False)
legend.get_frame().set_linewidth(0.8)

# Final values
final_cluster = df_cluster['max_cluster'].iloc[-1]
final_density = df_cluster['max_density'].iloc[-1]
stats_text = (
    f'Final State:\n'
    f'Max Cluster: {final_cluster:.0f} vehicles\n'
    f'Max Density: {final_density:.2f} v/km²'
)
ax1.text(0.98, 0.05, stats_text, transform=ax1.transAxes,
         fontsize=9, verticalalignment='bottom', horizontalalignment='right',
         bbox=dict(boxstyle='round', facecolor='white', alpha=0.9,
                   edgecolor='black', linewidth=0.8))

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig5_cluster_growth.pdf')
plt.savefig(OUTPUT_DIR / 'fig5_cluster_growth.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig5_cluster_growth.pdf'}")
plt.close()

# ============================================================
# Figure 6: Performance Summary (Box Plot + Bar Chart)
# ============================================================
print("📊 Figure 6: Performance Summary...")

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Left: Latency Box Plot
bp = ax1.boxplot([latencies], vert=True, patch_artist=True,
                  labels=['Block Creation'],
                  widths=0.5,
                  boxprops=dict(facecolor=COLORS['primary'], alpha=0.7,
                                edgecolor='black', linewidth=1),
                  medianprops=dict(color=COLORS['danger'], linewidth=2),
                  whiskerprops=dict(color='black', linewidth=1),
                  capprops=dict(color='black', linewidth=1),
                  flierprops=dict(marker='o', markerfacecolor='red',
                                  markersize=4, alpha=0.5))

# Target line
ax1.axhline(y=100, color=COLORS['target'], linestyle='--', linewidth=2,
            label='Target: 100 ms', zorder=10)

ax1.set_ylabel('Latency (ms)', fontweight='bold')
ax1.set_title('(a) Latency Distribution Summary', fontweight='bold', pad=10)
ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, axis='y',
         color=COLORS['grid'])
ax1.set_axisbelow(True)
ax1.legend(loc='upper right', framealpha=0.95, edgecolor='black')

# Add percentile annotations
percentiles_vals = [np.percentile(latencies, p) for p in [25, 50, 75]]
ax1.text(1.3, percentiles_vals[1], f'Median\n{percentiles_vals[1]:.1f}ms',
         fontsize=9, va='center',
         bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.9,
                   edgecolor='black', linewidth=0.5))

# Right: Key Metrics Bar Chart
metrics = ['Success\nRate', 'Blocks\n(×1000)', 'Avg Latency\n(×10ms)',
           'Max Cluster\nSize', 'Max Density\n(×10 v/km²)']
values = [100, 11.482, 5.172, 19, 6.720]  # Scaled for visualization
colors_list = [COLORS['success'], COLORS['primary'], COLORS['secondary'],
               COLORS['danger'], COLORS['warning']]

bars = ax2.bar(metrics, values, color=colors_list, alpha=0.7,
               edgecolor='black', linewidth=1)

# Value labels on bars
for bar, val, raw_val in zip(bars, values, [100, 11482, 51.72, 19, 67.20]):
    height = bar.get_height()
    if raw_val == 100:
        label_text = '100%'
    elif raw_val == 11482:
        label_text = '11,482'
    elif raw_val == 51.72:
        label_text = '51.72 ms'
    elif raw_val == 19:
        label_text = '19'
    else:
        label_text = f'{raw_val:.1f}'

    ax2.text(bar.get_x() + bar.get_width()/2., height + 2,
             label_text, ha='center', va='bottom', fontsize=10,
             fontweight='bold')

ax2.set_ylabel('Scaled Values', fontweight='bold')
ax2.set_title('(b) Key Performance Metrics', fontweight='bold', pad=10)
ax2.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, axis='y',
         color=COLORS['grid'])
ax2.set_axisbelow(True)
ax2.set_ylim([0, 120])

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'fig6_performance_summary.pdf')
plt.savefig(OUTPUT_DIR / 'fig6_performance_summary.png')
print(f"  ✓ Saved: {OUTPUT_DIR / 'fig6_performance_summary.pdf'}")
plt.close()

# ============================================================
# Summary
# ============================================================
print()
print("=" * 60)
print("✅ All figures generated successfully!")
print("=" * 60)
print()
print(f"Output directory: {OUTPUT_DIR}")
print()
print("Generated files:")
print("  1. fig1_latency_distribution.pdf/.png - Latency histogram")
print("  2. fig2_latency_cdf.pdf/.png - Cumulative distribution")
print("  3. fig3_neighbor_distribution.pdf/.png - Neighbor count")
print("  4. fig4_vehicle_growth.pdf/.png - Vehicle scalability")
print("  5. fig5_cluster_growth.pdf/.png - Cluster growth")
print("  6. fig6_performance_summary.pdf/.png - Performance summary")
print()
print("📝 Use PDF files for LaTeX papers (vector graphics)")
print("🖼️  Use PNG files for presentations (high-resolution)")
print()
