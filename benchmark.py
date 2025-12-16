import subprocess
import sys

def benchmark(num_runs: int, base_filename: str):
    """
    Runs main.py multiple times and generates indexed output files.
    """

    for i in range(1, num_runs + 1):
        # Construct the output filename using the base name and index
        output_filename = f"{base_filename}_{i}.txt"

        # Run main.py as a subprocess and redirect its output to a file
        with open(output_filename, "w") as output_file:
            subprocess.run(
                [sys.executable, "main.py"],  # Use the current Python interpreter
                stdout=output_file,           # Redirect standard output to file
                stderr=subprocess.PIPE,       # Capture errors (optional but recommended)
                text=True                     # Ensure text mode for output
            )

if __name__ == "__main__":
    N = int(sys.argv[1]) # number of runs

    filename = sys.argv[2] # filename

    # Execute main.py multiple times
    benchmark(N, filename)
