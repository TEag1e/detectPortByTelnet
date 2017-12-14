
因防火墙禁止或访问策略限制，无法利用ping命令检查网络是否可达，因此尝试telnet测试主机映射端口

脚本中所用的port_services.txt文件是借助nmap中的默认的端口_服务对应关系生成的

-----------------

Usage: 	python3 DetectPortByTelent.py target [-pn 端口数量] [-tt 目标线程] [-tp 端口线程] [-od 输出路径]

功能：通过telnet测试主机开放端口

positional arguments:
  target                指定目标主机host/ip,可以指定单个，也可以从文件中读取多个

optional arguments:
  -h, --help            show this help message and exit
  
  -tt THREADTARGET, --threadTarget THREADTARGET
                        扫描主机时的线程数，默认20
						
  -tp THREADPORT, --threadPort THREADPORT
                        扫描端口时的线程数，默认200
						
  -od OUTDIR, --outDir OUTDIR
                        结果输出到的目录，默认新建一个result目录
						
  -pn PORTNUMBER, --portNumber PORTNUMBER
                        指定要扫描的端口数量，默认1000
						
-----------------
