import pandas as pd
import matplotlib.pyplot as plt
import os

def generate_graph():
    csv_file = "tests/results/performance_telemetry_results.csv"
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} does not exist.")
        return

    df = pd.read_csv(csv_file)
    
    # Filter only successful TC-08 runs
    tc08_df = df[(df["test_case"] == "TC-08") & (df["result"] == "success")]
    
    if tc08_df.empty:
        print("No successful TC-08 data found.")
        return
        
    # Group by file size to get average throughput if there are multiple runs
    grouped = tc08_df.groupby("file_size_mb")["processing_throughput_mb_s"].mean().reset_index()
    
    plt.figure(figsize=(9, 5))
    plt.plot(grouped['file_size_mb'], grouped['processing_throughput_mb_s'], marker='o', color='#2ecc71', linewidth=2)
    
    plt.title('TC-08 Actual Measured Throughput Results')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Effective Throughput (MB/s)')
    plt.grid(True, linestyle='--', alpha=0.6)
    
    # Add explicit limits and padding
    plt.xlim(0, max(grouped['file_size_mb']) * 1.1)
    plt.ylim(0, max(grouped['processing_throughput_mb_s']) * 1.2)
    
    os.makedirs('tests/results/graphs', exist_ok=True)
    out_file = 'tests/results/graphs/tc08_throughput_graph.png'
    plt.savefig(out_file, dpi=300, bbox_inches='tight')
    print(f"Graph saved as {out_file}")

if __name__ == "__main__":
    generate_graph()
