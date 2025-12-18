# A Practical Usage of a Probability-Guided Grammar Fuzzer 

This project was a part of the final exam for [Practical Software Analysis](https://learnit.itu.dk/course/view.php?id=3024751) taught at the [IT-University of Copenhagen](https://www.itu.dk) in Autumn 2025 by [Mahsa Varshosaz](https://mahsavarshosaz.net) and [Andrzej Wasowski](https://www.itu.dk/~wasowski/). The project was developed by Lotte Juul Damgaard, Rakul Maria Hjalmarsdóttir Tórgarð and Sara Pissarra Gouveia Vieira.

## Package management

[`uv`](https://docs.astral.sh/uv/) is used for package management. For setting up the project, please install uv by following the [installation guide](https://docs.astral.sh/uv/getting-started/installation/). After installing, packages can be synced using the following command:

```console
uv sync
```

## About the project

This project demonstrates a practical usage of a probability-gyuided grammar fuzzer. The goal was to evaluate the effects of applying probabilistic strategies to guide a grammar expansion during input generation. This was done by extending on the fuzzer created by the [Fuzzingbook](https://www.fuzzingbook.org). The fuzzer was implemented focusing on a specific SUT, namely the OWASP Juice Shop, which is an open-source insecure web application. By exploiting the vulnerabilities known from the website's Login page, we managed to create a structured grammar that inputs SQL injections to the page.

## Running the Fuzzer

In order to run the Fuzzer, you will have to setup your computer with the package management system explained above.

Selenium is used as a driver for the fuzzer to test on, and is required to setup on your machine. Follow the [installation guide](https://selenium-python.readthedocs.io/installation.html) and download the chrome or firefox driver, which are the two drivers that this project supports.

Additionally, you will need to host the Juice Shop locally. Head over to the [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and following the Setup section in the `.README` file to clone and setup the project.

### Benchmarking the fuzzer

Once you have Selenium up and running and the Juice Shop is live on http://localhost:3000, you may start the benchmarking of the fuzzer. The benchmark will generate a results file from the benchmark, which will be placed in the `benchmark_results` folder. The `benchmark.py` takse three positional arguments:

- `n`: number of times, main is run
- `max_expansions`: number of max iterations, the grammar is expanded
- `filename`: the filename of the benchmark

For example, to run the benchmark on 10 iterations, expanding the grammar 30 times each iteration, and storing it in a file named TEST, run the following command from your terminal in the root folder of this project:

```bash
python benchmark.py 10 30 TEST
```

### Running the fuzzer once

You can also run the fuzzer a single time. This is done by executing the `main.py` file, which takes two positional arguments:

- `i`: number of times the file should be executed (in fact, ONLY used for the `benchmark.py`, so just put 1)
- `MAX_EXPANSION`: number of times the fuzzer should iterate/expand upon the grammar

For example, you could start the fuzzer and have it expand the grammar 10 times by running the following command from your terminal in the root folder of this project:

```bash
python main.py 1 10
```