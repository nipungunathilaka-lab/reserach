import psutil
import time

cpu_values = []
ram_values = []

print("=" * 50)
print("TC-09 CPU AND MEMORY MONITOR")
print("=" * 50)

print("\nMonitoring started...")
print("Start the file transfer now.")
print("After transfer + download is finished, press CTRL+C.\n")

try:
    while True:

        cpu = psutil.cpu_percent(interval=1)

        memory = psutil.virtual_memory()
        used_ram_mb = memory.used / (1024 * 1024)

        cpu_values.append(cpu)
        ram_values.append(used_ram_mb)

        print(
            f"CPU: {cpu:6.2f}% | "
            f"RAM Used: {used_ram_mb:8.2f} MB"
        )

except KeyboardInterrupt:

    if cpu_values and ram_values:

        avg_cpu = sum(cpu_values) / len(cpu_values)
        peak_cpu = max(cpu_values)

        avg_ram = sum(ram_values) / len(ram_values)
        peak_ram = max(ram_values)

        print("\n" + "=" * 50)
        print("TC-09 FINAL RESULT")
        print("=" * 50)

        print(f"Average CPU : {avg_cpu:.2f}%")
        print(f"Peak CPU    : {peak_cpu:.2f}%")
        print(f"Average RAM : {avg_ram:.2f} MB")
        print(f"Peak RAM    : {peak_ram:.2f} MB")

        print("=" * 50)
