import os
import sys
import unittest
import json
import platform

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

def dump_json(filename, data):
    dir_path = "tests/results/final_crypto_assurance"
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, filename), "w") as f:
        json.dump(data, f, indent=4)

def run_tests():
    print("="*80)
    print("FINAL NATIVE ML-KEM RUNTIME EVIDENCE-CLOSURE AUDIT")
    print("="*80)
    
    # Dump Environment
    env_data = {
        "os": f"{platform.system()} {platform.release()}",
        "python_version": sys.version,
        "architecture": platform.architecture()[0],
        "in_docker": os.path.exists("/.dockerenv")
    }
    dump_json("environment.json", env_data)
    
    import tests.security.test_crypto_assurance as test_crypto
    import tests.integration.test_real_transfer as test_real
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromModule(test_crypto))
    suite.addTests(loader.loadTestsFromModule(test_real))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Categorize results
    mlkem_results = {}
    hybrid_results = {}
    integration_results = {}
    fs_results = {}
    
    # We just do a simple pass/fail based on test names in the result
    all_tests = {}
    
    # Initialize all as pass if result was successful (it will be overridden if failed)
    # Actually it's easier to iterate the suite and check result.failures/errors
    
    failed_test_ids = [test.id().split('.')[-1] for test, _ in result.failures + result.errors]
    
    for test in test_crypto.TestCryptoAssurance.__dict__.keys():
        if test.startswith("test_"):
            status = "FAIL" if test in failed_test_ids else "PASS"
            all_tests[test] = status
            
    for test in test_real.TestRealTransferIntegration.__dict__.keys():
        if test.startswith("test_"):
            status = "FAIL" if test in failed_test_ids else "PASS"
            all_tests[test] = status

    for k, v in all_tests.items():
        if "mlkem" in k:
            mlkem_results[k] = v
        elif "hybrid" in k:
            hybrid_results[k] = v
        elif "fs" in k:
            fs_results[k] = v
        elif "integration" in k or "transfer" in k or "mitm" in k:
            integration_results[k] = v
            
    dump_json("mlkem_runtime.json", mlkem_results)
    dump_json("hybrid_runtime.json", hybrid_results)
    dump_json("integration_transfer.json", integration_results)
    dump_json("forward_secrecy.json", fs_results)
    
    summary = {
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "overall_status": "VERIFIED" if result.wasSuccessful() else "FAILED"
    }
    dump_json("test_summary.json", summary)
    
    if result.wasSuccessful():
        print("\n[+] Audit execution complete. All tests PASSED natively.")
        sys.exit(0)
    else:
        print("\n[-] Audit execution failed. Some tests FAILED or ERRORed.")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
