import os
import math
import pandas as pd
import pytest

def test_mock_files_not_in_active_directory():
    """Ensure mock files are not in the active source tree."""
    mock_files = [
        "backend/simulate_throughput.py",
        "backend/throughput_results_mock.csv",
        "backend/throughput_graph.png"
    ]
    for mock_file in mock_files:
        assert not os.path.exists(mock_file), f"Mock artifact {mock_file} is still in active directory!"

def test_tc08_evidence_provenance():
    """Ensure real TC-08 tests do not contain fallback values and are mathematically sound."""
    csv_file = "tests/results/performance_telemetry_results.csv"
    if not os.path.exists(csv_file):
        pytest.skip(f"{csv_file} does not exist yet. Run TC-08 tests first.")
        
    df = pd.read_csv(csv_file)
    tc08_df = df[df["test_case"] == "TC-08"]
    
    if tc08_df.empty:
        pytest.skip("No TC-08 results found in CSV.")
        
    for index, row in tc08_df.iterrows():
        # Check for mock fallback values
        assert row["processing_throughput_mb_s"] not in [120.5, 15.2, 45.3], f"Row {index} contains hardcoded mock performance value!"
        
        # If it failed, no fake data should exist
        if row["result"] != "success":
            assert row["processing_throughput_mb_s"] == 0, f"Failed run generated fake throughput: {row['processing_throughput_mb_s']}"
            continue
            
        # Mathematical verification
        file_size_mb = row["file_size_mb"]
        exec_time_ms = row["execution_time_ms"]
        recorded_throughput = row["processing_throughput_mb_s"]
        recorded_bandwidth = row["processing_bandwidth_mbps"]
        
        exec_time_s = exec_time_ms / 1000.0
        
        assert exec_time_s > 0, f"Execution time must be > 0, got {exec_time_s}"
        assert file_size_mb > 0, f"File size must be > 0, got {file_size_mb}"
        
        expected_throughput = file_size_mb / exec_time_s
        expected_bandwidth = expected_throughput * 8
        
        # Verify throughput matches calculation (within tolerance for floating point)
        assert math.isclose(recorded_throughput, expected_throughput, rel_tol=1e-2), \
            f"Throughput mismatch: recorded {recorded_throughput}, expected {expected_throughput}"
            
        # Verify bandwidth matches calculation
        assert math.isclose(recorded_bandwidth, expected_bandwidth, rel_tol=1e-2), \
            f"Bandwidth mismatch: recorded {recorded_bandwidth}, expected {expected_bandwidth}"

if __name__ == "__main__":
    test_mock_files_not_in_active_directory()
    test_tc08_evidence_provenance()
    print("All tests passed successfully!")
