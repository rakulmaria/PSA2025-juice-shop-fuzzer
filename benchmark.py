import subprocess
import sys
import time

def benchmark(N, max_expansions, filename):
    output_filename = f"benchmark_results/{filename}_benchmark.txt"

    start = time.time()
    with open(output_filename, "w") as output_file:
        for i in range(1, N + 1):
            subprocess.run(
                [sys.executable, "main.py", str(i), max_expansions],
                stdout=output_file,
                stderr=subprocess.PIPE,
                text=True
            )

    end = time.time()

    # Append final timing information to the output_file
    with open(output_filename, "a") as output_file:
        output_file.write(f"\n Full test-suite timing:\n")
        output_file.write(f"   Total elapsed time:       {end-start:.4f} s\n")
        output_file.write("\n" + "=" * 50 + "\n")

if __name__ == "__main__":
    n = int(sys.argv[1])         # number of times, main is run
    max_expansions = sys.argv[2] # number of max iterations, the grammar is expanded
    filename = sys.argv[3]       # filename

    benchmark(n, max_expansions, filename)
