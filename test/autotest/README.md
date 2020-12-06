### Environment
* Python >= 3.6
* poetry

Poetry Installation (https://python-poetry.org/docs/)
```shell script
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
```

### Usage
Install dependencies in a virtual environment
```shell script
    poetry install
```
### Test
```shell script
    poetry run python authoritative_test.py
    peotry run python recursive_test.py
```
