"""
因防火墙禁止或访问策略限制，无法利用ping命令检查网络是否可达，因此尝试telnet测试主机映射端口
脚本中所用的port_services.txt文件是借助nmap中的默认的端口_服务对应关系生成的
"""

import sys
import os
import telnetlib
import argparse
from concurrent.futures import ThreadPoolExecutor


def get_args():
    parser = argparse.ArgumentParser(description="功能：通过telnet测试主机开放端口")
    parser.add_argument("target", help="指定目标主机host/ip,可以指定单个，也可以从文件中读取多个")
    parser.add_argument("-tt", "--threadTarget", default=20, type=int, help="扫描主机时的线程数，默认20")
    parser.add_argument("-tp", "--threadPort", default=200, type=int, help="扫描端口时的线程数，默认200")
    parser.add_argument("-od", "--outDir", default="result", help="结果输出到的目录，默认result")
    parser.add_argument("-pn", "--portNumber", default=1000, type=int, help="指定要扫描的端口数量，默认1000")
    return parser.parse_args()


# 探测一个目标的一个端口
def detect_port(target, port, port_services, result_file):
    try:
        print(target, port, ' ... ')
        telnetlib.Telnet(target, port, timeout=5)
        line = f'{target} {port} {port_services.get(port)}'
        print(line)
        result_file.write(line + '\n')
        return line
    except:
        pass


# 探测一个目标开启的所有端口
def detect_target(target, args):
    var_target = target.replace('.', '_')
    thread_port = args.threadPort if args.threadPort <= args.portNumber else args.portNumber
    port_numbers = args.portNumber
    # 格式化文件内的端口信息
    port_services = {}
    with open('port_services.txt')as p_file:
        for line in p_file.readlines():
            line = line.strip().split()
            port_services[line[0]] = line[1]
    # 多线程探测端口
    futures = []
    directroy = args.outDir
    if not os.path.exists(directroy):
        os.mkdir(directroy)
        # 将扫描结果写入到对应的文件内
    with open(f"{directroy}//{var_target}.txt", 'a')as result_file:
        with ThreadPoolExecutor(thread_port)as executor:
            for port in list(port_services)[:port_numbers]:
                futures.append(executor.submit(detect_port, target, port, port_services, result_file))
    result[target] = futures


def main():
    # 获取命令行参数
    args = get_args()
    # 为了保证在所有扫描结束时，统一输出扫描结果
    global result
    result = {}
    # 第一个参数如果是文件则逐行读取，如果不是文件则认为是手动指定的ip/域名
    if os.path.exists(args.target):
        target_file = args.target
        # 使文件内的目标格式化
        with open(target_file)as t_file:
            targets = [target.strip() for target in t_file.readlines()]
        # 多线程探测目标，如果设置的线程数大于目标数量，则设置最大线程数为目标数量
        max_thread = len(targets) if len(targets) <= get_args().threadTarget else get_args().threadTarget
        with ThreadPoolExecutor(max_thread) as executor:
            for target in targets:
                executor.submit(detect_target, target ,args)
    else:
        target = args.target
        detect_target(target ,args)
    # 在扫描结束后，输出扫描结果
    for host in result:
        print('\n\n-------%s ports are as follows-------\n\n' % host)
        for info in result[host]:
            if info.result():
                print(info.result())
        print('\n\n******* %s ports ********************\n\n' % host)


if __name__ == '__main__':
    main()
