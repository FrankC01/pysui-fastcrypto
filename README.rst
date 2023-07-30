================
pysui-fastcrypto
================

pysui-fastcrypto is a Python wrapper library for `MytenLab/fastcrypto <https://github.com/MystenLabs/fastcrypto>`_.

The primary use of this library is for `pysui <https://github.com/FrankC01/pysui>`_. It is not intended for general usage
although others are not prevented from using it.

Building pysui-fastcrypto for Python
-------------------------------------

1. Clone this repo
2. Install Python (3.10+)
3. Create a virtual environment - ``python3 -m venv env``
4. Activate the environment - ``. env/bin/activate``
5. Update pip if needed - ``pip install -U pip``
6. Install maturin - ``pip install maturin``
7. Build the crate and python wrapper - ``maturin develop``

The last step will compile the Rust crate and create a Python wheel and install `pysui-fastcrypto` in the virtual environment.

Installing pysui-fastcrypto from PyPi
--------------------------------------

1. Install Python (3.10+)
2. Create a virtual environment - ``python3 -m venv env``
3. Activate the environment - ``. env/bin/activate``
4. Update pip if needed - ``pip install -U pip``
5. Install pysui-fastcrypto - ``pip install pysui-fastcrypto``

The last step will compile the Rust crate and create a Python wheel and install `pysui-fastcrypto` in the virtual environment.

Documentation for pysui-fastcrypto
----------------------------------

1. Run - ``cargo doc --open``
