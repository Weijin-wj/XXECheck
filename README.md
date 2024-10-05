# XXECheck
[Englist](README.en.md)

## 简介

这是一个 XXE 漏洞检测工具，支持 DoS 检测（DoS 检测默认开启）和 DNSLOG 两种检测方式，能对普通 xml 请求和 xlsx 文件上传进行 XXE 漏洞检测。

## 使用说明

对普通请求进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 `--nodos`

```
python3 XXECheck.py -t request -f 1.txt -d dnslog
```

如果不指定请求包，则会生成检测 POC，手工检测

```
python3 XXECheck.py -t request -d dnslog
```

对 xlsx 上传功能进行检测，指定请求包为 1.txt，-d 添加 dnslog 链接，不加只进行 DoS 检测，如果不想使用 DoS 检测请添加 `--nodos`

```
python3 XXECheck.py -t xlsx -f 1.txt -d dnslog
```

如果不指定请求包，则会生成带有 POC 的 xlsx 文件，手工检测

```
python3 XXECheck.py -t xlsx -d dnslog
```

完整参数

```
$ python3 XXECheck.py -h

optional arguments:
  -h, --help            显示帮助信息
  -t {request,xlsx}, --type {request,xlsx}
                        支持两种类型，request 代表普通请求，xlsx 代表 xlsx 文件上传
  -d DNS, --dns DNS     DNSLOG 链接
  -f FILE, --file FILE  保存请求包的文件路径，例如 burp 请求包
  --nodos               禁止使用 DoS 检测

```

## 免责声明

本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行测试。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
