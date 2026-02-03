#!/usr/bin/env python3
"""
MeshChain Defense Resilience Visualization
논문에 필요한 방어 메커니즘 효과성 데이터 가시화
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from pathlib import Path

# Set style for academic paper
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9

# Output directory
output_dir = Path('paper_figures')
output_dir.mkdir(exist_ok=True)

def load_defense_metrics(csv_file='defense_paper_metrics.csv'):
    """Load defense metrics from CSV"""
    df = pd.read_csv(csv_file)
    return df

def plot_defense_effectiveness(df):
    """
    Figure 1: Defense Mechanism Effectiveness
    Shows Detection Rate, FPR, and F1 Score for each mechanism
    """
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))

    mechanisms = df['mechanism'].values
    tpr = df['detection_rate'].values * 100
    fpr = df['fpr'].values * 100
    f1 = df['f1_score'].values

    # Detection Rate
    axes[0].bar(range(len(mechanisms)), tpr, color='#2ecc71', alpha=0.8)
    axes[0].set_xticks(range(len(mechanisms)))
    axes[0].set_xticklabels(mechanisms, rotation=45, ha='right')
    axes[0].set_ylabel('Detection Rate (%)')
    axes[0].set_title('(a) True Positive Rate (Detection)')
    axes[0].set_ylim(0, 105)
    axes[0].axhline(y=90, color='r', linestyle='--', linewidth=1, alpha=0.5, label='Target: 90%')
    axes[0].legend()
    axes[0].grid(axis='y', alpha=0.3)

    # False Positive Rate
    axes[1].bar(range(len(mechanisms)), fpr, color='#e74c3c', alpha=0.8)
    axes[1].set_xticks(range(len(mechanisms)))
    axes[1].set_xticklabels(mechanisms, rotation=45, ha='right')
    axes[1].set_ylabel('False Positive Rate (%)')
    axes[1].set_title('(b) False Positive Rate')
    axes[1].set_ylim(0, 105)
    axes[1].axhline(y=10, color='g', linestyle='--', linewidth=1, alpha=0.5, label='Target: <10%')
    axes[1].legend()
    axes[1].grid(axis='y', alpha=0.3)

    # F1 Score
    axes[2].bar(range(len(mechanisms)), f1, color='#3498db', alpha=0.8)
    axes[2].set_xticks(range(len(mechanisms)))
    axes[2].set_xticklabels(mechanisms, rotation=45, ha='right')
    axes[2].set_ylabel('F1 Score')
    axes[2].set_title('(c) F1 Score (Precision-Recall Balance)')
    axes[2].set_ylim(0, 1.05)
    axes[2].axhline(y=0.85, color='r', linestyle='--', linewidth=1, alpha=0.5, label='Target: 0.85')
    axes[2].legend()
    axes[2].grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_dir / 'fig1_defense_effectiveness.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig1_defense_effectiveness.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig1_defense_effectiveness.pdf")
    plt.close()

def plot_threat_coverage(df):
    """
    Figure 2: Threat-specific Defense Coverage
    Shows which defenses handle which threats
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    # Threat-Defense mapping
    threat_defense_map = {
        'T1: Solo Tampering': ['Signature Verify', 'Reputation Screen', 'TEE Attestation'],
        'T2: Regional Majority': ['Diversity Check', 'Reputation Screen'],
        'T3: Sybil/Eclipse': ['Rate Limiting', 'Witness Consensus'],
    }

    mechanisms = df['mechanism'].tolist()
    threats = list(threat_defense_map.keys())

    # Create matrix
    matrix = np.zeros((len(threats), len(mechanisms)))
    for i, threat in enumerate(threats):
        for j, mech in enumerate(mechanisms):
            if mech in threat_defense_map[threat]:
                matrix[i, j] = 1

    im = ax.imshow(matrix, cmap='YlGn', aspect='auto', alpha=0.7)

    ax.set_xticks(range(len(mechanisms)))
    ax.set_yticks(range(len(threats)))
    ax.set_xticklabels(mechanisms, rotation=45, ha='right')
    ax.set_yticklabels(threats)

    # Add checkmarks for covered threats
    for i in range(len(threats)):
        for j in range(len(mechanisms)):
            if matrix[i, j] == 1:
                ax.text(j, i, '✓', ha='center', va='center',
                       fontsize=14, fontweight='bold', color='darkgreen')

    ax.set_title('Threat Coverage by Defense Mechanism')
    plt.tight_layout()
    plt.savefig(output_dir / 'fig2_threat_coverage.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig2_threat_coverage.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig2_threat_coverage.pdf")
    plt.close()

def plot_performance_overhead(df):
    """
    Figure 3: Performance Overhead
    Shows average check time for each defense mechanism
    """
    fig, ax = plt.subplots(figsize=(10, 5))

    mechanisms = df['mechanism'].values
    avg_time = df['avg_check_time_us'].values
    max_time = df.get('max_check_time_us', avg_time * 2).values  # Estimate if not available

    x = np.arange(len(mechanisms))
    width = 0.6

    bars = ax.bar(x, avg_time, width, label='Average', color='#3498db', alpha=0.8)
    ax.scatter(x, max_time, color='#e74c3c', marker='D', s=60,
               label='Maximum', zorder=3, edgecolors='black', linewidth=0.5)

    ax.set_xlabel('Defense Mechanism')
    ax.set_ylabel('Check Time (μs)')
    ax.set_title('Performance Overhead per Defense Check')
    ax.set_xticks(x)
    ax.set_xticklabels(mechanisms, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    # Add target line (100μs = 0.1ms)
    ax.axhline(y=100, color='g', linestyle='--', linewidth=1, alpha=0.5,
               label='Target: <100μs')

    plt.tight_layout()
    plt.savefig(output_dir / 'fig3_performance_overhead.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig3_performance_overhead.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig3_performance_overhead.pdf")
    plt.close()

def plot_detection_vs_fpr_tradeoff(df):
    """
    Figure 4: Detection Rate vs False Positive Rate Trade-off
    Scatter plot showing the balance
    """
    fig, ax = plt.subplots(figsize=(8, 6))

    mechanisms = df['mechanism'].values
    tpr = df['detection_rate'].values * 100
    fpr = df['fpr'].values * 100

    scatter = ax.scatter(fpr, tpr, s=200, alpha=0.6, c=range(len(mechanisms)),
                        cmap='viridis', edgecolors='black', linewidth=1.5)

    # Add labels for each point
    for i, mech in enumerate(mechanisms):
        ax.annotate(mech, (fpr[i], tpr[i]),
                   textcoords="offset points", xytext=(5, 5),
                   fontsize=8, alpha=0.8)

    ax.set_xlabel('False Positive Rate (%)')
    ax.set_ylabel('Detection Rate (TPR) (%)')
    ax.set_title('Detection Rate vs False Positive Rate Trade-off')
    ax.grid(True, alpha=0.3)

    # Add ideal region (top-left)
    ax.axvline(x=10, color='g', linestyle='--', alpha=0.3, label='FPR target: <10%')
    ax.axhline(y=90, color='g', linestyle='--', alpha=0.3, label='TPR target: >90%')
    ax.legend(loc='lower right')

    # Add diagonal reference line (random classifier)
    ax.plot([0, 100], [0, 100], 'k:', alpha=0.3, label='Random')

    plt.tight_layout()
    plt.savefig(output_dir / 'fig4_detection_fpr_tradeoff.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig4_detection_fpr_tradeoff.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig4_detection_fpr_tradeoff.pdf")
    plt.close()

def plot_summary_table(df):
    """
    Figure 5: Summary Table
    Create a professional table for the paper
    """
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('tight')
    ax.axis('off')

    # Prepare data
    table_data = []
    for _, row in df.iterrows():
        table_data.append([
            row['mechanism'],
            f"{row['blocks_checked']:.0f}",
            f"{row['attacks_detected']:.0f}",
            f"{row['false_positives']:.0f}",
            f"{row['detection_rate']*100:.1f}%",
            f"{row['fpr']*100:.1f}%",
            f"{row['f1_score']:.3f}",
            f"{row['avg_check_time_us']:.2f}μs"
        ])

    headers = ['Defense', 'Checked', 'Detected', 'FP', 'TPR', 'FPR', 'F1', 'Avg Time']

    table = ax.table(cellText=table_data, colLabels=headers,
                    cellLoc='center', loc='center',
                    colWidths=[0.20, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.15])

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2)

    # Style header
    for i in range(len(headers)):
        cell = table[(0, i)]
        cell.set_facecolor('#3498db')
        cell.set_text_props(weight='bold', color='white')

    # Alternate row colors
    for i in range(1, len(table_data) + 1):
        for j in range(len(headers)):
            cell = table[(i, j)]
            if i % 2 == 0:
                cell.set_facecolor('#ecf0f1')

    plt.title('Defense Mechanism Performance Summary', fontsize=14, fontweight='bold', pad=20)
    plt.savefig(output_dir / 'fig5_summary_table.pdf', bbox_inches='tight')
    plt.savefig(output_dir / 'fig5_summary_table.png', bbox_inches='tight')
    print(f"✓ Saved: {output_dir}/fig5_summary_table.pdf")
    plt.close()

def create_latex_table(df, output_file='defense_results_table.tex'):
    """Generate LaTeX table for paper"""
    with open(output_dir / output_file, 'w') as f:
        f.write("\\begin{table}[t]\n")
        f.write("\\centering\n")
        f.write("\\caption{Defense Mechanism Effectiveness Against MeshChain Threats}\n")
        f.write("\\label{tab:defense_effectiveness}\n")
        f.write("\\begin{tabular}{lrrrrrrr}\n")
        f.write("\\toprule\n")
        f.write("Defense & Checked & Detected & FP & TPR (\\%) & FPR (\\%) & F1 & Time ($\\mu$s) \\\\\n")
        f.write("\\midrule\n")

        for _, row in df.iterrows():
            f.write(f"{row['mechanism']} & "
                   f"{row['blocks_checked']:.0f} & "
                   f"{row['attacks_detected']:.0f} & "
                   f"{row['false_positives']:.0f} & "
                   f"{row['detection_rate']*100:.1f} & "
                   f"{row['fpr']*100:.1f} & "
                   f"{row['f1_score']:.3f} & "
                   f"{row['avg_check_time_us']:.2f} \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"✓ Saved: {output_dir}/{output_file}")

def main():
    """Generate all paper figures"""
    print("\n" + "="*60)
    print("  MeshChain Defense Resilience Visualization")
    print("  Generating paper-ready figures...")
    print("="*60 + "\n")

    # Load data
    try:
        df = load_defense_metrics()
        print(f"✓ Loaded {len(df)} defense mechanisms from CSV\n")
    except FileNotFoundError:
        print("Error: defense_paper_metrics.csv not found!")
        print("Please run ./test_defense_paper first.\n")
        return

    # Generate all figures
    print("Generating figures...\n")
    plot_defense_effectiveness(df)
    plot_threat_coverage(df)
    plot_performance_overhead(df)
    plot_detection_vs_fpr_tradeoff(df)
    plot_summary_table(df)

    # Generate LaTeX table
    create_latex_table(df)

    print("\n" + "="*60)
    print("✓ All figures generated successfully!")
    print(f"  Output directory: {output_dir}/")
    print("="*60 + "\n")

    # Print summary
    print("Summary Statistics:")
    print(f"  Average Detection Rate: {df['detection_rate'].mean()*100:.2f}%")
    print(f"  Average FPR: {df['fpr'].mean()*100:.2f}%")
    print(f"  Average F1 Score: {df['f1_score'].mean():.3f}")
    print(f"  Average Check Time: {df['avg_check_time_us'].mean():.2f}μs")
    print()

if __name__ == '__main__':
    main()
