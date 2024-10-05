# XXECheck

## Introduction

This is an XXE vulnerability detection tool that supports DoS detection (DoS detection is enabled by default) and DNSLOG detection methods. It can detect XXE vulnerabilities in regular XML requests and XLSX file uploads.

## Usage

Detect ordinary requests, specify the request packet as 1.txt, -d adds the dnslog link, and if not added, only DoS detection will be performed. If you do not want to use DoS detection, please add `--nodos`

```
python3 XXECheck.py -t request -f 1.txt -d dnslog
```

If no request packet is specified, a detection POC will be generated for manual detection

```
python3 XXECheck.py -t request -d dnslog
```

Test the xlsx upload function, specify the request package as 1.txt, add a dnslog link with -d; without it, only perform DoS testing. If you do not want to use DoS testing, please add `--nodos`

```
python3 XXECheck.py -t xlsx -f 1.txt -d dnslog
```

If no request package is specified, an xlsx file with POC will be generated for manual inspection.

```
python3 XXECheck.py -t xlsx -d dnslog
```

Complete parameters

```
$ python3 XXECheck.py -h

optional arguments:
  -h, --help            show this help message and exit
  -t {request,xlsx}, --type {request,xlsx}
                        Specify the type of operation: 'request' for a normal
                        request, 'xlsx' for uploading an XLSX file.
  -d DNS, --dns DNS     DNS request link.
  -f FILE, --file FILE  Request data file path.
  --nodos               Prohibit the use of DOS detection.
```

## Disclaimer

This tool is intended solely for legally authorized enterprise security construction activities. If you need to test the availability of this tool, please set up your own target environment.

When using this tool for detection, you should ensure that such activities comply with local laws and regulations and that you have obtained sufficient authorization. Do not test unauthorized targets.

If you engage in any illegal activities while using this tool, you will bear the corresponding consequences, and we will not assume any legal or joint liability.

Unless you have fully read, completely understood, and accepted all the terms of this agreement, please do not use this tool. Your use or any other explicit or implicit indication of acceptance of this agreement will be regarded as your acknowledgment that you have read and agree to abide by the terms of this agreement.