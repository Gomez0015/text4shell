# Installation
```sh
git clone https://giturl.com
cd text4shell && pip install -r requirements.txt
```

# Usage

## Scan URL(s) forms and try injecting payload
```sh
python text4shell.py -u <URL>
```
OR
```sh
python text4shell.py -uf <URL_FILE>
```

## Attempt injection on a specific parameter(s)
```sh
python text4shell.py -u <URL> -p <PARAM>
```
OR
```sh
python text4shell.py -u <URL> -pf <PARAM_FILE>
```

Was tested using this tutorial:
https://infosecwriteups.com/text4shell-poc-cve-2022-42889-f6e9df41b3b7