import subprocess
import sys

def benchmark(N, max_expansions, filename):
    output_filename = f"{filename}_benchmark.txt"

    with open(output_filename, "w") as output_file:
        for i in range(1, N + 1):

            subprocess.run(
                [sys.executable, "main.py", str(i), max_expansions],
                stdout=output_file,
                stderr=subprocess.PIPE,
                text=True
            )


if __name__ == "__main__":
    n = int(sys.argv[1])         # number of times, main is run
    max_expansions = sys.argv[2] # number of max iterations, the grammar is expanded
    filename = sys.argv[3]       # filename

    benchmark(n, max_expansions, filename)
