## Linux 入侵检测脚本

### 功能设计:
* V1.0主要功能用来采集信息
* V1.1主要功能将原始数据进行分析,并找出存在可疑或危险项
* V1.2增加基线检查的功能

### Linux主机安全检查:
* 首先采集原始信息保存到$dir/${ipadd}_${date}/checkresult.txt
* 将系统日志、应用日志打包并保存到$dir/${ipadd}_${date}/log下
* 在检查过程中若发现存在问题则直接输出到$dir/${ipadd}_${date}/danger_file.txt
* 使用过程中若在windows下修改再同步到Linux下，请使用dos2unix工具进行格式转换,不然可能会报错
* 在使用过程中必须使用root账号,不然可能导致某些项无法分析
### 如何使用:
* 本脚本可以单独运行,单独运行中只需要将本脚本上传到相应的服务器中,然后sh 即可
### 检查内容
* IP及版本
* 端口情况
* 网络连接
* 网卡模式
* 自启动项
* 定时任务
* 路由与路由转发
* 进程分析
* 关键文件检查
* 运行服务
* 登录情况
* 用户与用户组
* 历史命令
* 策略与配置
* 可疑文件
* 系统日志分析
* 内核检查
* 安装软件
* 性能分析
* 共享情况
