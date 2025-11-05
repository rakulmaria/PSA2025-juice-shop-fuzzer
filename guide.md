# Installation guide

We use UV for package management and this guide should help you set the environment up.

## Step 1: install uv [(link to installation guide)](https://docs.astral.sh/uv/getting-started/installation/)

```bash
pip install uv
```

After installation, you should be able to sync the packages in the project

```bash
uv sync
````

## Step 2: install graphviz

Installation guide for windows: https://graphviz.org/download/
Install version 14.0.2 

> Ensure the Graphviz bin directory is added to your PATH. Example: `C:\Program Files\Graphviz\bin`

Verify it works:

```bash
dot -V
```

## Step 3: Install fuzzingbook

> uv pip install fuzzingbook

My laptop had issues finding the `graphviz/cgraph.h` header, so I had to export some flags. Explicitly telling the compiler where to find Graphviz worked for me (your graphviz installation might be located somewhere else):

```bash
export CFLAGS="-I/opt/homebrew/include"
export LDFLAGS="-L/opt/homebrew/lib"
uv pip install fuzzingbook
```