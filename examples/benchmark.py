import statistics
import subprocess
import time
from pathlib import Path

from rich.pretty import pprint
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

# Parameters
runs = 1
ciphers = list(range(4))
compressions = list(range(4))
input_file = Path("benchmark_input.txt")
output_file = Path("benchmark_output.zxtx")
certificate = "certificate.pem"
public_key = "public_key.pem"
private_key = "private_key.pem"

# Ensure input file exists
input_file.write_text("This is a benchmark test file.\n" * 1000)


# Benchmark function
def benchmark_command(cmd):
    start = time.perf_counter()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.perf_counter()
    return end - start


# Rich progress setup
progress = Progress(
    SpinnerColumn(speed=1.5),
    "[progress.description]{task.description}",
    BarColumn(),
    "[progress.percentage]{task.percentage:>3.0f}%",
    TextColumn("[green]{task.completed}/{task.total}[/]"),
    TimeElapsedColumn(),
    TimeRemainingColumn(),
)

results = []

with progress:
    total_tasks = len(ciphers) * len(compressions) * 3 * runs  # write, read, dump
    task = progress.add_task("Benchmarking ZXTX operations", total=total_tasks)

    for _ in range(runs):
        for cipher in ciphers:
            for compression in compressions:
                output_zxtx = output_file.with_name(
                    f"output_c{cipher}_k{compression}.zxtx"
                )

                write_cmd = [
                    "zxtx",
                    "write",
                    str(input_file),
                    str(output_zxtx),
                    "--cipher",
                    str(cipher),
                    "--compression",
                    str(compression),
                    "--certificate",
                    certificate,
                    "--public-key",
                    public_key,
                    "--private-key",
                    private_key,
                ]
                read_cmd = [
                    "zxtx",
                    "read",
                    str(output_zxtx),
                    "--cipher",
                    str(cipher),
                    "--compression",
                    str(compression),
                    "--certificate",
                    certificate,
                    "--public-key",
                    public_key,
                    "--private-key",
                    private_key,
                ]
                dump_cmd = [
                    "zxtx",
                    "dump",
                    str(output_zxtx),
                    "--cipher",
                    str(cipher),
                    "--compression",
                    str(compression),
                    "--certificate",
                    certificate,
                    "--public-key",
                    public_key,
                    "--private-key",
                    private_key,
                ]

                write_time = benchmark_command(write_cmd)
                progress.update(task, advance=1)

                read_time = benchmark_command(read_cmd)
                progress.update(task, advance=1)

                dump_time = benchmark_command(dump_cmd)
                progress.update(task, advance=1)

                results.append(
                    {
                        "cipher": cipher,
                        "compression": compression,
                        "write_time": write_time,
                        "read_time": read_time,
                        "dump_time": dump_time,
                    }
                )

# Show summarized benchmark results
results_summary = {
    "total_cases": len(results),
    "avg_write": statistics.mean(r["write_time"] for r in results),
    "avg_read": statistics.mean(r["read_time"] for r in results),
    "avg_dump": statistics.mean(r["dump_time"] for r in results),
    "max_write": max(results, key=lambda r: r["write_time"]),
    "max_read": max(results, key=lambda r: r["read_time"]),
    "max_dump": max(results, key=lambda r: r["dump_time"]),
}

pprint(results_summary)
