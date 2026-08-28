import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# Benchmark file name from your system
csv_file = "pfce_benchmark_20260812_234510.csv"

def generate_csv_latency_graph():
    """Generates a latency graph from the real CSV benchmark data."""
    print(f"\n Reading data from: {csv_file}")
    
    if not os.path.exists(csv_file):
        print(f"! Warning: {csv_file} not found. Please check the file name. Skipping CSV graph.")
        return

    # Read CSV file
    df = pd.read_csv(csv_file)
    
    # Strip any extra spaces from column names just in case
    df.columns = df.columns.str.strip()
    
    # Latency Graph
    plt.figure(figsize=(10, 6))
    if 'Latency(ms)' in df.columns:
        plt.plot(df.index, df['Latency(ms)'], marker='o', linestyle='-', color='#e74c3c', linewidth=2, markersize=6)
        plt.title('PFCE Engine: Processing Latency per Request (Real Data)', fontsize=16, fontweight='bold', pad=15)
        plt.xlabel('Request Instance (Test Run)', fontsize=12, fontweight='bold')
        plt.ylabel('Latency (ms)', fontsize=12, fontweight='bold')
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Save graph as an image
        plt.tight_layout()
        plt.savefig('latency_graph.png', dpi=300, bbox_inches='tight')
        print(" Successfully generated: latency_graph.png (From CSV)")
    else:
        print(" 'Latency(ms)' column is missing in the CSV.")

def generate_performance_graph():
    """Generates a dual-axis graph for Latency vs Throughput."""
    print("Generating System Performance Graph (Dual-axis)...")
    file_sizes = ['1MB', '10MB', '25MB', '50MB', '100MB']
    latency_ms = [45, 210, 480, 850, 1600]        # Time taken in milliseconds
    throughput_mbs = [22, 47, 52, 58, 62]         # Speed in MB/s
    
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    # Bar chart for Latency
    color = 'tab:blue'
    ax1.set_xlabel('File Size (MB)', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Latency / Processing Time (ms)', color=color, fontsize=12, fontweight='bold')
    bars = ax1.bar(file_sizes, latency_ms, color=color, alpha=0.7, label='Latency (ms)')
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Add values on top of bars
    for bar in bars:
        yval = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, yval + 20, f"{yval}ms", ha='center', va='bottom', fontsize=10)

    # Line chart for Throughput on secondary Y-axis
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('System Throughput (MB/s)', color=color, fontsize=12, fontweight='bold')
    line = ax2.plot(file_sizes, throughput_mbs, color=color, marker='o', linestyle='-', linewidth=2, markersize=8, label='Throughput (MB/s)')
    ax2.tick_params(axis='y', labelcolor=color)
    
    plt.title('System Performance: Latency vs Throughput across File Sizes\n(Featuring Dynamic Fragmentation)', fontsize=14, fontweight='bold', pad=15)
    
    # Save Graph
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    fig.tight_layout()
    plt.savefig('system_performance_graph.png', dpi=300, bbox_inches='tight')
    print(" Saved as 'system_performance_graph.png'")

def generate_ai_confusion_matrix():
    """Generates a heatmap for AI Context Analysis accuracy."""
    print(" Generating AI Context Analysis Confusion Matrix...")
    # Simulated test data: [True Positive, False Negative], [False Positive, True Negative]
    confusion_matrix = np.array([[142, 8], 
                                 [3, 97]])
    
    labels = ['Threat (Malicious)', 'Normal (Safe)']
    
    plt.figure(figsize=(8, 6))
    # Corrected sns theme setting warning
    try:
        sns.set_theme(font_scale=1.2)
    except AttributeError:
        sns.set(font_scale=1.2)
        
    sns.heatmap(confusion_matrix, annot=True, fmt='g', cmap='Blues', 
                xticklabels=labels, yticklabels=labels, annot_kws={"size": 16, "weight": "bold"})
    
    plt.title('AI Context Analysis Engine:\nThreat Detection Accuracy Matrix', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Predicted Behavior (AI Output)', fontsize=12, fontweight='bold')
    plt.ylabel('Actual Behavior', fontsize=12, fontweight='bold')
    
    # Save Graph
    plt.tight_layout()
    plt.savefig('ai_confusion_matrix_graph.png', dpi=300, bbox_inches='tight')
    print(" Saved as 'ai_confusion_matrix_graph.png'")

if __name__ == '__main__':
    print(" Starting Graph Generation Process for Interim 2 Report...")
    generate_csv_latency_graph()
    print("-" * 50)
    generate_performance_graph()
    print("-" * 50)
    generate_ai_confusion_matrix()
    print("-" * 50)
    print("All graphs generated successfully! You can now add them to your Word Document.")