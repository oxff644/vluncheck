!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#######################################################################
#Linux安全检查与应急响应辅助工具
#date: 2021-03-03
#System Required:  Redhat7+
########################################################################
dir="/tmp/default"
#定义检查log信息的存储目录

cat <<EOF
*********************************************
功能设计:
1.V1.0主要功能用来采集信息
2.V1.1主要功能将原始数据进行分析,并找出存在可疑或危险项
3.V1.2增加基线检查的功能
4.V1.3可以进行相关危险项或可疑项的自动处理

Linux主机安全检查:
1.首先采集原始信息保存到$dir/${ipadd}_${date}/checkresult.txt
2.将系统日志、应用日志打包并保存到$dir/${ipadd}_${date}/log下
3.在检查过程中若发现存在问题则直接输出到$dir/${ipadd}_${date}/danger_file.txt
4.使用过程中若在windows下修改再同步到Linux下，请使用dos2unix工具进行格式转换,不然可能会报错
5.在使用过程中必须使用root账号,不然可能导致某些项无法分析
如何使用:
1.本脚本可以单独运行,单独运行中只需要将本脚本上传到相应的服务器中,然后sh 即可
2.另外本脚本可以作为多台服务器全面检查的安全检查模板,本脚本不需要手工运行,只需要将相应服务器的IP、账号、密码写到hosts.txt文件中，然后sh login.sh即可
检查内容
0.IP及版本
1.端口情况
2.网络连接
3.网卡模式
4.自启动项
5.定时任务
6.路由与路由转发
7.进程分析
8.关键文件检查
9.运行服务
10.登录情况
11.用户与用户组
12.历史命令
13.策略与配置
14.可疑文件
16.系统日志分析>
17.内核检查>
18.安装软件
20.性能分析
21.共享情况
==============================================
EOF

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && UPPDATE_TEXT_COLOR="\E[1;31m"
RES="\E[0m"
Info="${Green_font_prefix}[OK]${Font_color_suffix}"
Tip="${Red_font_prefix}[注意]${Font_color_suffix}"
date=$(date +%Y%m%d)
ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
check_file="$dir/${ipadd}_${date}/checkresult.txt"
danger_file="$dir/${ipadd}_${date}/danger_file.txt"


check_root(){
[[ $EUID != 0 ]] && echo -e "${Error} 当前账号非ROOT(或没有ROOT权限),无法继续操作,请使用${Green_background_prefix} sudo su$RES来获取临时ROOT权限" && exit 1
}
check_root

check_sys(){
if [[ -f /etc/redhat-release ]]; then
release="centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
release="debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
release="ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
release="centos"
elif cat /proc/version | grep -q -E -i "debian"; then
release="debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
release="ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
release="centos"
fi
bit=`uname -m`
}



get_ip(){
ip=$(wget -qO- -t1 -T2 ipinfo.ioa/ip)
echo "$ip"
if [[ -z "${ip}" ]]; then
ip=$(wget -qO- -t1 -T2 api.ip.sba/ip)
echo "$ip"
if [[ -z "${ip}" ]]; then
ip=$(wget -qO- -t1 -T2 members.3322.org/dyndnsa/getip)
echo "$ip"
if [[ -z "${ip}" ]]; then
ip="VPS_IP"
echo "$ip"
fi
fi
fi
}

check_sys
[[ ${release} != "centos" ]] && echo -e "${Error}本脚本不支持当前系统$RES ${release} !" && exit 1

mkdir   -p  $dir/${ipadd}_${date}/
for    i  in    $check_file    $danger_file   ;do sudo touch ${i}; done


saveresult="tee -a $check_file"

echo "环境变量:" && env | $saveresult
echo -------------0.1IP地址-------------------
get_ip
echo  "本机公网出口地址信息:$1"  | $saveresult
echo "[*]本机IP地址信息:" && echo "$ipadd"| $saveresult
echo -------------0.2版本信息------------------
#corever=$(uname -a)
echo "[*]系统内核版本信息:" && uname -a  | $saveresult
systemver=$(cat /etc/redhat-release)
echo "[*]系统发行版本:" && echo "$systemver" | $saveresult
printf "\n" | $saveresult
# -------------0.3 ARP------------------
echo "[0.3.1]正在查看ARP表项....." | $saveresult
arp=$(arp -a -n)
arpattack=$(arp -a -n | awk '{++S[$4]} END {for(a in S) {if($2>1) print $2,a,S[a]}}')
if [ -n "$arp" ];then
(echo "[*]ARP表项如下:" && echo "$arp") | $saveresult
if [ -n "$arpattack" ];then
(echo -e  "${Tip}发现存在ARP攻击$RES:" && echo "$arpattack") | tee -a $danger_file | $saveresult
else
echo "[*]未发现ARP攻击" | $saveresult
fi
else
echo "[未发现arp表]" | $saveresult
fi
printf "\n" | $saveresult


#------------查看tcp 端口情况-----------------
#只有绑定在0.0.0.0其他主机请求才可以建立
listenport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
echo "[*]该服务器占用TCP端口以及对应的服务:" && echo "$listenport" | $saveresult
accessport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$accessport" ];then
(echo -e "${Tip}以下TCP端口面向局域网其他主机或互联网开放连接,请注意!$RES" && echo "$accessport") |tee -a $danger_file |  $saveresult
else
echo "[*]端口未面向局域网其他或互联网开放" | $saveresult
fi
printf "\n" | $saveresult

# ------------- 查看UDP开放端口--------------
udpopen=$(netstat -anlup | awk  '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
udpports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
if [ -n "$udpopen" ];then
(echo "[*]该服务器开放UDP端口以及对应的服务:" && echo "$udpopen") | $saveresult
if [ -n "$udpports" ];then
echo -e  "${Tip}该服务器开放UDP端口以及对应的服务$RES:" | tee -a $danger_file | $saveresult
for port in $udpports
do
nc -uz 127.0.0.1 $port
if [ $? -eq 0 ];then
echo $port  | $saveresult
fi
done
else
echo "[*]未发现在UDP端口面向局域网或互联网开放连接." | $saveresult
fi
else
echo "[*]系统未开放UDP端口" | $saveresult
fi
printf "\n" | $saveresult

# -------------1.2 TCP高危端口--------------
echo "[1.2]正在检查TCP高危端口....." | $saveresult
tcpport=`netstat -anlpt | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
dangerstcpports="20 21 23 25 110 389 512 513 514 873 1194 1352 1433 1521 1723 3128   3306 3690 5000 5432 5900   6379 27017 27018 50070 50030  "
if [ -n "$tcpport" ];then
for port in $tcpport
do
for i in $dangerstcpports
do
tcpport=`echo $i | awk -F "[:]" '{print $1}'`
# desc=`echo $i | awk -F "[:]" '{print $2}'`
# process=`echo $i | awk -F "[:]" '{print $3}'`
if [ $tcpport == $port ];then
echo   "$tcpport" | tee -a $danger_file | $saveresult
count=count+1
fi
done
done
fi
if [ $count = 0 ];then
echo "[*]未发现TCP危险端口" | $saveresult
else
echo -e   "${Tip}请人工对TCP危险端口进行关联分析与确认${RES}" | $saveresult
fi
printf "\n" | $saveresult

# -------------1.3 UDP高危端口--------------
echo "[1.3]正在检查UDP高危端口....."
udpport=`netstat -anlpu | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
dangersudpports="161 53 69 "
if [ -n "$udpport" ];then
for port in $udpport
do
for i in $dangersudpports
do
udpport=`echo $i | awk -F "[:]" '{print $1}'`
#      desc=`echo $i | awk -F "[:]" '{print $2}'`
#      process=`echo $i | awk -F "[:]" '{print $3}'`
if [ $udpport == $port ];then
echo "$udpport" | tee -a $danger_file | $saveresult
count=count+1
fi
done
done
fi
if [ $count = 0 ];then
echo "[*]未发现UDP危险端口" | $saveresult
else
echo -e  "${Tip}请人工对UDP危险端口进行关联分析与确认${RES} "
fi
printf "\n" | $saveresult


echo ------------2.网络连接---------------------
echo "[2.1]正在检查网络连接情况....." | $saveresult
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -na | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
(echo "[*]网络连接情况:" && echo "$netstat") | $saveresult
if [ -n "$netstatnum" ];then
(echo "[*]各个状态的数量如下:" && echo "$netstatnum") | $saveresult
fi
else
echo "[*]未发现网络连接" | $saveresult
fi
printf "\n" | $saveresult
# -------------3.网卡模式---------------------
echo "检查网卡模式....." | $saveresult
ifconfigmode=$(ifconfig -a | grep flags | awk -F '[: = < >]' '{print "网卡:",$1,"模式:",$5}')
echo "网卡工作模式如下:" && echo "$ifconfigmode" | $saveresult
printf "\n" | $saveresult
echo "[3.2]正在分析是否有网卡处于混杂模式....." | $saveresult
Promisc=`ifconfig | grep PROMISC | gawk -F: '{ print $1}'`
if [ -n "$Promisc" ];then
(echo -e  "${Tip}网卡处于混杂模式:$RES" && echo "$Promisc") | tee -a $danger_file | $saveresult
else
echo "[*]未发现网卡处于混杂模式" | $saveresult
fi
printf "\n" | $saveresult
echo "[3.3]正在分析是否有网卡处于监听模式....." | $saveresult
Monitor=`ifconfig | grep -E "Mode:Monitor" | gawk -F: '{ print $1}'`
if [ -n "$Monitor" ];then
(echo -e "${Tip}网卡处于监听模式:$RES" && echo "$Monitor") | tee -a $danger_file | $saveresult
else
echo "[*]未发现网卡处于监听模式" | $saveresult
fi
printf "\n" | $saveresult


#-------------4.启动项-----------------------
echo "[4.1]正在检查用户自定义启动项....." | $saveresult
chkconfig=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig" ];then
(echo -e "${Tip}用户自定义启动项:$RES" && echo "$chkconfig") | $saveresult
else
echo "[*]未发现用户自定义启动项" | $saveresult
fi
printf "\n" | $saveresult
echo "[4.2]正在检查系统自启动项....." | $saveresult
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
(echo "[*]系统自启动项如下:" && echo "$systemchkconfig")  | $saveresult
else
echo "[*]未发现系统自启动项" | $saveresult
fi
printf "\n" | $saveresult
echo "[4.3]正在检查危险启动项....." | $saveresult
dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)$")
if [ -n "$dangerstarup" ];then
(echo -e  "${Tip}发现危险启动项:$RES" && echo "$dangerstarup") | tee -a $danger_file | $saveresult
else
echo "[*]未发现危险启动项" | $saveresult
fi
printf "\n" | $saveresult


# ------------5.查看定时任务-------------------
# "正在分析系统定时任务....." | $saveresult
syscrontab=$(more /etc/crontab |grep -v '^#\|^$\|^[A-Z]')
if [ -n  "$syscrontab" ];then
echo "[!!!]发现存在系统定时任务:" && echo  "$syscrontab"  | tee -a $danger_file | $saveresult
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
if [ $? -eq 0 ];then
(echo -e  "${Tip}发现下面的定时任务可疑,请注意$RES" && echo "$dangersyscron") | tee -a $danger_file | $saveresult
else
echo "[*]未发现可疑系统定时任务" | $saveresult
fi
else
echo "[*]未发现系统定时任务" | $saveresult
fi
printf "\n" | $saveresult
# if [ $? -eq 0 ]表示上面命令执行成功;执行成功输出的是0；失败非0
# if [ $? != 0 ]表示上面命令执行失败
# ------------5.2分析用户定时任务-------------------
ucron=$(getent passwd   | awk  -F  ':' '{if($7!="/sbin/nologin")print $1 }' |  xargs -I {} crontab -l -u {})
if [ -n "$ucron" ];then
echo -e "${Tip}发现用户定时任务如下:$RES" && echo "$ucron" |tee -a $danger_file | $saveresult

danger_crontab=${ucron} | egrep "((chmod|useradd|groupadd|chattr)|((wget|curl).*\.(sh|pl|py)))"
if [ $? -eq 0 ];then
(echo "[!!!]发现可疑定时任务,请注意！！！" && echo "$danger_crontab") | tee -a $danger_file | $saveresult
else
echo "[*]未发现可疑定时任务" | $saveresult
fi
printf "\n" | $saveresult
else
echo "[*]未发现用户定时任务"  | $saveresult
fi
printf "\n" | $saveresult

# -------------6.路由与路由转发----------------
echo "[6.1]正在检查路由表....." | $saveresult
route=$(route -n)
echo "[*]路由表如下:" && echo "$route" | $saveresult
printf "\n" | $saveresult
echo "[6.2]正在分析是否开启转发功能....." | $saveresult
#数值分析
#1:开启路由转发
#0:未开启路由转发
ip_forward=`more /proc/sys/net/ipv4/ip_forward `
#if [ -n "$ip_forward" ];then
if [ $ip_forward==1 ];then
echo "该服务器开启路由转发,请注意！" | tee -a $danger_file  | $saveresult
else
echo "[*]该服务器未开启路由转发" | $saveresult
fi
printf "\n" | $saveresult
# ------------7.进程分析--------------------
ps=`ps -elf  | awk  -F ' ' '{if ($5 != "2") print $3,  $15 }'|uniq`
echo "[*]系统进程如下:" && echo "$ps"| $saveresult
printf "\n" | $saveresult
echo "[7.2]正在检查守护进程....." | $saveresult
if [ -e /etc/xinetd.d/rsync ];then
(echo "[*]系统守护进程:" && more /etc/xinetd.d/rsync | grep -v "^#") | $saveresult
else
echo "[*]未发现守护进程" | $saveresult
fi
printf "\n" | $saveresult



# ------------8.1DNS文件检查-----------------
echo "  [8.1]正在检查DNS文件....."
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}')
if [ -n "$resolv" ];then
(echo "[*]该服务器使用以下DNS服务器:" && echo "$resolv")
else
echo "[*]未发现DNS服务器"
fi
printf "\n"
#------------8.2hosts文件检查-----------------
echo "[8.2]正在检查hosts文件....." | $saveresult
hosts=$(more /etc/hosts)
if [ -n "$hosts" ];then
(echo "[*]hosts文件如下:" && echo "$hosts") | $saveresult
else
echo "[*]未发现hosts文件" | $saveresult
fi
printf "\n" | $saveresult

# ------------8.3公钥文件检查-----------------
echo "[8.3]正在检查公钥文件....." | $saveresult
if [  -e /root/.ssh/*.pub ];then
echo "[!!!]发现公钥文件,请注意！"  | tee -a $danger_file | $saveresult
else
echo "[*]未发现公钥文件" | $saveresult
fi
printf "\n" | $saveresult
# ------------8.4私钥文件检查-----------------
echo "[8.4]正在检查私钥文件....." | $saveresult
if [ -e /root/.ssh/id_rsa ];then
echo "[!!!]发现私钥文件,请注意！" | tee -a $danger_file | $saveresult
else
echo "[*]未发现私钥文件" | $saveresult
fi
printf "\n" | $saveresult



echo ------------9.运行服务----------------------
echo "[9.1]正在检查运行服务....." | $saveresult
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
echo "[*]以下服务正在运行：" && echo "$services"| $saveresult
printf "\n" | $saveresult
echo ------------10.查看登录用户------------------
(echo "[*]系统登录用户:" && who ) | $saveresult
printf "\n" | $saveresult


echo ------------11.1超级用户---------------------
#UID=0的为超级用户,系统默认root的UID为0
echo "[11.1]正在检查是否存在超级用户....." | $saveresult
Superuser=`more /etc/passwd | egrep -v '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}'`
if [ -n "$Superuser" ];then
echo "${Tip} 除root外发现超级用户:$RES" | tee -a $danger_file | $saveresult

for user in $Superuser
do
echo $user | $saveresult
if [ "${user}" = "toor" ];then
echo "[!!!]BSD系统默认安装toor用户,其他系统默认未安装toor用户,若非BSD系统建议删除该账号" | $saveresult
fi
done
else
echo "[*]未发现超级用户" | $saveresult
fi
printf "\n" | $saveresult
echo ------------11.2克隆用户---------------------
#相同的UID为克隆用户
echo "[11.2]正在检查是否存在克隆用户....." | $saveresult
uid=`awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd`
if [ -n "$uid" ];then
echo "[!!!]发现下面用户的UID相同:" | tee -a $danger_file | $saveresult
(more /etc/passwd | grep $uid | awk -F: '{print $1}') | tee -a $danger_file | $saveresult
else
echo "[*]未发现相同UID的用户" | $saveresult
fi
printf "\n" | $saveresult
echo ------------11.3可登录用户-------------------
echo "[11.3]正在检查可登录的用户......" | $saveresult
loginuser=`cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}'`
if [ -n "$loginuser" ];then
echo "以下用户可以登录：" | tee -a $danger_file | $saveresult
for user in $loginuser
do
echo $user | tee -a $danger_file | $saveresult
done
else
echo "[*]未发现可以登录的用户" | $saveresult
fi
printf "\n" | $saveresult
echo ------------11.4非系统用户-----------------
echo "[11.4]正在检查非系统本身自带用户" | $saveresult
if [ -f /etc/login.defs ];then
uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
(echo "系统最小UID为"$uid) | $saveresult
nosystemuser=`gawk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
if [ -n "$nosystemuser" ];then
(echo "以下用户为非系统本身自带用户:" && echo "$nosystemuser") | tee -a $danger_file | $saveresult
else
echo "[*]未发现除系统本身外的其他用户" | $saveresult
fi
fi
printf "\n" | $saveresult
# ------------11.6空口令用户-----------------
echo "[11.6]正在检查空口令用户....." | $saveresult
nopasswd=`gawk -F: '($2=="") {print $1}' /etc/shadow`
if [ -n "$nopasswd" ];then
(echo "[!!!]以下用户口令为空：" && echo "$nopasswd") | $saveresult
else
echo "[*]未发现空口令用户" | $saveresult
fi
printf "\n" | $saveresult
# ------------11.7空口令且可登录-----------------
echo "[11.7]正在检查空口令且可登录的用户....." | $saveresult
#允许空口令用户登录方法
#1.passwd -d username
#2.echo "PermitEmptyPasswords yes" >>/etc/ssh/sshd_config
#3.service sshd restart
aa=$(cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}')
bb=$(gawk -F: '($2=="") {print $1}' /etc/shadow)
cc=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
flag=""
for a in $aa
do
for b in $bb
do
if [ "$a" = "$b" ] && [ -n "$cc" ];then
echo "[!!!]发现空口令且可登录用户:"$a | $saveresult
flag=1
fi
done
done
if [ -n "$flag" ];then
echo "请人工分析配置和账号" | $saveresult
else
echo "[*]未发现空口令且可登录用户" | $saveresult
fi
printf "\n" | $saveresult
# ------------11.8口令未加密----------------
echo "[11.8]正在检查口令加密用户....." | $saveresult
noenypasswd=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd)
if [ -n "$noenypasswd" ];then
(echo "[!!!]以下用户口令未加密:" && echo "$noenypasswd") | tee -a $danger_file | $saveresult
else
echo "[*]未发现口令未加密的用户"  | $saveresult
fi
printf "\n" | $saveresult
# ------------11.9用户组分析-----------------------
echo "[*]用户组信息如下:"
(more /etc/group | grep -v "^#") | $saveresult
printf "\n" | $saveresult
echo ------------11.9.2 特权用户组 --------------------
echo "[11.9.2]正在检查特权用户组....." | $saveresult
roots=$(more /etc/group | grep -v '^#' | gawk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -n "$roots" ];then
echo "${Tip}除root用户外root组还有以下用户:" | tee -a $danger_file | $saveresult

for user in $roots
do
echo $user | tee -a $danger_file | $saveresult
done
else
echo "[*]除root用户外root组未发现其他用户" | $saveresult
fi
printf "\n" | $saveresult
echo ------------11.9.3 相同GID用户组--------------------
echo "[11.9.3]正在检查相应GID用户组....." | $saveresult
groupuid=$(more /etc/group | grep -v "^$" | awk -F: '{print $3}' | uniq -d)
if [ -n "$groupuid" ];then
(echo "[!!!]发现相同GID用户组:" && echo "$groupuid") | tee -a $danger_file | $saveresult
else
echo "[*]未发现相同GID的用户组" | $saveresult
fi
printf "\n" | $saveresult
echo ------------11.9.4 相同用户组名--------------------
echo "[11.9.4]正在检查相同用户组名....." | $saveresult
groupname=$(more /etc/group | grep -v "^$" | awk -F: '{print $1}' | uniq -d)
if [ -n "$groupname" ];then
(echo "[!!!]发现相同用户组名:" && echo "$groupname") | tee -a $danger_file | $saveresult
else
echo "[*]未发现相同用户组名" | $saveresult
fi
printf "\n" | $saveresult

# ------------11.10 文件权限--------------------
etc=$(ls -l / | grep etc | awk '{print $1}')
if [ "${etc:1:9}" = "rwxr-x---" ]; then
echo "[*]/etc/权限为750,权限正常" | $saveresult
else
echo "[!!!]/etc/文件权限为:""${etc:1:9}","权限不符合规划,权限应改为750" | $saveresult
fi
printf "\n" | $saveresult



files1=("
/etc/gshadow
/etc/securetty
/etc/grub2.cfg
/etc/security/limits.conf
/etc/xinetd.d
/etc/shadow*
")


files2=("
/etc/passwd
/etc/group
/etc/services
")

echo "[11.10.2]正在检查文件权限....." | $saveresult
for  af1 in $files1
do
shadow=$(ls -l $af1 | awk '{print $1}')
if [ "${shadow:1:9}" = "rw-------" ]; then
echo " $af1文件权限为600,权限符合规范" | $saveresult
else
echo " $af1文件权限为:""${shadow:1:9}"",不符合规范,权限应改为600" | tee -a $danger_file | $saveresult
fi
done


for  af2 in $files2
do
shadow=$(ls -l $af2 | awk '{print $1}')
if [ "${passwd:1:9}" = "rw-r--r--" ]; then
echo " $af1文件权限为644,权限符合规范" | $saveresult
else
echo " $af2文件权限为:""${shadow:1:9}"",不符合规范,权限应改为644" | tee -a $danger_file | $saveresult
fi
done


# "------------11.10limits.conf文件权限"
cat /etc/security/limits.conf | grep -v ^# | grep core
if [ $? -eq 0 ];then
soft=`cat /etc/security/limits.conf | grep -v ^# | grep core | awk -F ' ' '{print $2}'`
for i in $soft
do
if [ $i = "soft" ];then
echo "* soft core 0 已经设置,符合要求" | $saveresult
fi
if [ $i = "hard" ];then
echo "* hard core 0 已经设置,符合要求" | $saveresult
fi
done
else
echo "没有设置core,建议在/etc/security/limits.conf中添加* soft core 0和* hard core 0"  | $saveresult
fi
echo ------------11.11其他--------------------
#Access:访问时间,每次访问文件时都会更新这个时间,如使用more、cat
#Modify:修改时间,文件内容改变会导致该时间更新
#Change:改变时间,文件属性变化会导致该时间更新,当文件修改时也会导致该时间更新;但是改变文件的属性,如读写权限时只会导致该时间更新，不会导致修改时间更新
echo "[11.11]正在检查useradd时间属性....." | $saveresult
echo "[*]useradd时间属性:" | $saveresult
stat /usr/sbin/useradd | egrep "Access|Modify|Change" | grep -v '(' | $saveresult
printf "\n" | $saveresult
echo "[11.11]正在检查userdel时间属性....." | $saveresult
echo "[*]userdel时间属性:" | $saveresult
stat /usr/sbin/userdel | egrep "Access|Modify|Change" | grep -v '(' | $saveresult
printf "\n" | $saveresult
echo ------------12历史命令--------------------------
his=$(more /root/.bash_history)
scripts=`$his | egrep  "((wget|curl).*\.(sh|pl|py)$)" | grep -v grep`
addusers=`$his | egrep "(useradd|groupadd)" | grep -v grep`
delusers=`$his | egrep "(userdel|groupdel)" | grep -v grep`
danger_histroy=`$his | egrep  "(whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)" | grep -v grep`
uploadfiles=`$his | grep sz | grep -v grep | awk '{print $3}'`
if [ -e "/root/.bash_history" ];then
# (echo "[*]操作系统历史命令如下:" && echo "$history") | $saveresult

if [ -n "$scripts" ];then
(echo "[!!!]该服务器下载过脚本以下脚本：" && echo "$scripts") | tee -a $danger_file | $saveresult
else
echo "[*]该服务器未下载过脚本文件" | $saveresult
fi

if [ -n "$addusers" ];then
(echo "[!!!]该服务器增加过以下账号:" && echo "$addusers") | tee -a $danger_file | $saveresult
else
echo "[*]该服务器未增加过账号" | $saveresult
fi
printf "\n" | $saveresult

if [ -n "$delusers" ];then
(echo "[!!!]该服务器删除过以下账号:" && echo "$delusers") | tee -a $danger_file | $saveresult
else
echo "[*]该服务器未删除过账号" | $saveresult
fi

if [ -n "$danger_histroy" ];then
(echo "[!!!]发现可疑历史命令" && echo "$danger_histroy") | tee -a $danger_file | $saveresult
else
echo "[*]未发现可疑历史命令" | $saveresult
fi
printf "\n" | $saveresult

if [ -n "$uploadfiles" ];then
(echo "[!!!]通过历史日志发现本地主机下载过以下文件:" && echo "$uploadfiles") | $saveresult
else
echo "[*]通过历史日志未发现本地主机下载过文件" | $saveresult
fi

else
echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | $saveresult
fi

printf "\n" | $saveresult


echo ------------12.2mysql数据库操作历史命令---------------
echo "[12.2]正在检查数据库操作历史命令....." | $saveresult
mysql_history=$(more /root/.mysql_history |sed  's/\\040/ /g')
if [ -e "/root/.mysql_history" ];then
(echo "[*]数据库操作历史命令如下:" && echo "$mysql_history") | $saveresult
else
echo "[*]未发现数据库历史命令" | $saveresult
fi
printf "\n" | $saveresult
echo ------------13.策略情况---------------------
firewalledstatus=$(systemctl status firewalld | grep "active (running)")
firewalledpolicy=`firewall-cmd  --list-all`
if [ -n "$firewalledstatus" ];then
echo "[*]该服务器防火墙已打开"
if [ -n "$firewalledpolicy" ];then
(echo "[*]防火墙策略如下:" && echo "$firewalledpolicy")
else
echo "[!!!]防火墙策略未配置,建议配置防火墙策略!" | tee -a $danger_file | $saveresult
fi
else
echo  -e  "${Tip}防火墙未开启,建议开启防火墙${RES}" | tee -a $danger_file | $saveresult
fi


#------------13.2.1远程允许策略-----------------
hostsallow=$(more /etc/hosts.allow | grep -v '#')
if [ -n "$hostsallow" ];then
(echo "[!!!]允许以下IP远程访问:" && echo "$hostsallow") | tee -a $danger_file | $saveresult
else
echo "[*]hosts.allow文件未发现允许远程访问地址" | $saveresult
fi
printf "\n" | $saveresult
# ------------13.2.2远程拒绝策略-----------------
echo "[13.2.2]正在检查远程拒绝策略....." | $saveresult
hostsdeny=$(more /etc/hosts.deny | grep -v '#')
if [ -n "$hostsdeny" ];then
(echo "[!!!]拒绝以下IP远程访问:" && echo "$hostsdeny") | $saveresult
else
echo "[*]hosts.deny文件未发现拒绝远程访问地址" | $saveresult
fi
printf "\n" | $saveresult
echo ------------13.3密码策略------------------------
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`
passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'`
passlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`
passage=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}'`
if [ $passmax -le 90 -a $passmax -gt 0 ] &&  [ $passmin -ge 6 ]  &&  [ $passlen -ge 11 ] &&  [ $passage -ge 30 -a $passage -lt $passmax ] ;then
echo " ok  " | $saveresult
else
(echo 密码策略需要完善,策略如下: && more /etc/login.defs | grep ^[^#]| grep "PASS" )   | $saveresult
printf "\n"
echo  -e  "参考: \nPASS_MAX_DAYS<=90 \nPASS_MIN_DAYS>=6 \nPASS_MIN_LEN>= 8 \nPASS_WARN_AGE>=30 "
fi


#echo "[13.3.1]正在检查密码复杂度策略....." | $saveresult
(echo "[*]密码复杂度策略如下:" && more /etc/pam.d/system-auth | grep -v "#") | $saveresult
printf "\n" | $saveresult
echo ------------13.3.3 密码已过期用户---------------------------
echo "[13.3.3]正在检查密码已过期用户....." | $saveresult
NOW=$(date "+%s")
day=$((${NOW}/86400))
passwdexpired=$(grep -v ":[\!\*x]([\*\!])?:" /etc/shadow | awk -v today=${day} -F: '{ if (($5!="") && (today>$3+$5)) { print $1 }}')
if [ -n "$passwdexpired" ];then
(echo "[*]以下用户的密码已过期:" && echo "$passwdexpired")  | $saveresult
else
echo "[*]未发现密码已过期用户" | $saveresult
fi
printf "\n" | $saveresult
echo ------------13.3.4 账号超时锁定策略---------------------------
echo "[13.3.4]正在检查账号超时锁定策略....." | $saveresult
account_timeout=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'`
if [ "$account_timeout" != ""  ];then
TMOUT=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'`
if [ $TMOUT -le 600 -a $TMOUT -ge 10 ];then
echo "[*]账号超时时间为${TMOUT}秒,符合要求" | $saveresult
else
echo "[!!!]账号超时时间为${TMOUT}秒,不符合要求,建议设置小于600秒" | $saveresult
fi
else
echo "[!!!]账号超时未锁定,不符合要求,建议设置小于600秒" | $saveresult
fi
printf "\n" | $saveresult
echo ------------13.3.5 grub密码策略检查---------------------------
echo "[13.3.5]正在检查grub密码策略....." | $saveresult
grubpass=$(cat /etc/grub.conf | grep password)
if [ $? -eq 0 ];then
echo "[*]已设置grub密码,符合要求" | $saveresult
else
echo "[!!!]未设置grub密码,不符合要求,建议设置grub密码" | $saveresult
fi
printf "\n" | $saveresult

#lico  由 grup 替代
#------------13.4selinux策略----------------------
echo  "selinux 现在状态  "  && sestatus  | $saveresult
(echo "selinux策略如下:" && egrep -v '#|^$' /etc/sysconfig/selinux ) | $saveresult
printf "\n" | $saveresult




# ------------13.5sshd配置文件--------------------
sshdconfig=$(more /etc/ssh/sshd_config | egrep -v "#|^$")
emptypasswd=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
nopasswd=`gawk -F: '($2=="") {print $1}' /etc/shadow*`
if [ -s "/etc/ssh/sshd_config" ];then
(echo "[*]sshd配置文件如下:" && echo "$sshdconfig") | $saveresult
if [ -n "$emptypasswd" ];then
echo "[!!!]允许空口令登录,请注意！！！"
if [ -n "$nopasswd" ];then
(echo "[!!!]以下用户空口令:" && echo "$nopasswd") | tee -a $danger_file | $saveresult
else
echo "[*]但未发现空口令用户" | $saveresult
fi
fi
printf "\n" | $saveresult

`cat /etc/ssh/sshd_config | grep -v ^# |grep "PermitRootLogin no"`
if [ $? -eq 0 ];then
echo "[*]root不允许登陆,符合要求" | $saveresult
else
echo -e "${Tip}允许root远程登陆,不符合要求,建议关闭${RES}" | $saveresult
fi
else
echo -e "${Tip}未发现 /etc/ssh/sshd_config 配置文件${RES}" | $saveresult
fi
printf "\n" | $saveresult


# ------------13.6 NIS 配置文件--------------------
echo "[13.6]正在检查nis配置....." | $saveresult
nisconfig=$(more /etc/nsswitch.conf | egrep -v '#|^$')
if [ -n "$nisconfig" ];then
(echo "[*]NIS服务配置如下:" && echo "$nisconfig") | $saveresult
else
echo "[*]未发现NIS服务配置" | $saveresult
fi
printf "\n" | $saveresult
echo ------------13.7 Nginx配置----------------------
nginx=`find  / -name  nginx.conf`
if [ -n "$nginx" ];then
(echo "[*]Nginx配置文件位置:" && echo "$nginx" ) | $saveresult
else
echo "[*]未发现Nginx服务" | $saveresult
fi
printf "\n" | $saveresult
# ------------13.8 SNMP配置检查-------------
public=$(cat /etc/snmp/snmpd.conf | grep public | grep -v ^# | awk '{print $4}')
private=$(cat /etc/snmp/snmpd.conf | grep private | grep -v ^# | awk '{print $4}')
#-eq只支持整数的比较
if [ -f /etc/snmp/snmpd.conf ];then
if [[ "$public" == "public" ]];then
echo -e  "${Tip} 发现snmp服务存在默认团体名public,不符合要求${RES}" | $saveresult
fi
if [[ "$private" == "private" ]];then
echo -e "${Tip}发现snmp服务存在默认团体名private,不符合要求${RES}" | $saveresult
fi
else
echo "snmp服务配置文件不存在" | $saveresult
fi
#------------14. 可疑文件-------------------------
echo "[14.1]正在检查脚本文件....." | $saveresult
#scripts=$(find / *.* | egrep "\.(py|sh|per|pl)$" | egrep -v "/usr|/etc|/var")
scripts=`find / *.*   -mtime -30    | egrep "\.(py|sh|per|pl|php|asp|jsp)$"`
if [ -n "scripts" ];then
(echo -e "${Tip} 发现以下脚本文件,请注意！！！${RES}" && echo "$scripts") | tee -a $danger_file | $saveresult
else
echo "[*]未发现异常脚本文件" | $saveresult
fi
printf "\n" | $saveresult
echo ------------14.2 恶意文件---------------------
#webshell这一块因为技术难度相对较高,并且已有专业的工具，目前这一块建议使用专门的安全检查工具来实现
#系统层的恶意文件建议使用rootkit专杀工具来查杀,如rkhunter,下载地址:http://rkhunter.sourceforge.net
echo ------------14.3 最近24小时内变动的文件---------------------
#查看最近24小时内有改变的文件
(find / -mtime 0 | grep -E "\.(py|sh|per|pl|php|asp|jsp)$") | tee -a $danger_file | $saveresult
printf "\n" | $saveresult
echo ------------14.4 文件属性---------------------
files3=("
/etc/passwd
/etc/shadow
/etc/gshadow
/etc/group
")
flag=0
for  ff in  $file ;
do

for ((x=1;x<=15;x++))
do
apend=`lsattr ${ff} | cut -c $x`
if [ $apend == "i" ];then

echo "$ff 文件存在i安全属性,符合要求" | $saveresult
flag=1
fi
if [ $apend == "a" ];then
echo "$ff 文件存在a安全属性" | $saveresult
flag=1
fi
done
if [ $flag == 0 ];then
echo -e"${Tip}  $ff 没有设置相关安全属性!!!${RES}" | tee -a $danger_file | $saveresult
fi
done

printf "\n" | $saveresult
#------------16 日志分析------------------------------
logconf=$(more /etc/rsyslog.conf | grep ^[^#])
if [ -n "$logconf" ];then
(echo "[*]日志配置如下:" && echo "$logconf") | $saveresult
else
echo -e "${Tip} 未发现/etc/rsyslog.conf${RES}" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult
# ------------16.1.3 日志审核是否开启---------------
echo "[16.1.3]正在分析日志审核是否开启....." | $saveresult
service auditd status | grep running
if [ $? -eq 0 ];then
echo "[*]系统日志审核功能已开启,符合要求" | $saveresult
else
echo -e  "${Tip}系统日志审核功能已关闭,不符合要求,建议开启${RES}" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

#------------16.2secure日志分析---------------
logdir="/var/log"
logdirfile=(/var/log/secure*)
loginsuccess=$(less $logdirfile | grep "Accepted password" | awk '{print $1,$2,$3,$9,$11}')
loginfailed=$(less $logdirfile | grep "Failed password" | awk '{print $1,$2,$3,$9,$11}')
systemlogin=$(less $logdirfile | egrep "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
newusers=$(less $logdirfile | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
newgoup=$(less $logdirfile | grep "new group"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -e "$logdir" ]   && [ -s "$logdirfile" ]  ;then
if [ -n "$loginsuccess" ];then
(echo "[*]日志中分析到以下用户成功登录:" && echo "$loginsuccess")  | $saveresult
(echo "[*]登录成功的IP及次数如下：" && grep "Accepted " /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c )  | $saveresult
(echo "[*]登录成功的用户及次数如下:" && grep "Accepted" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c )  | $saveresult
else
echo "[*]日志中未发现成功登录的情况" | $saveresult
fi
if [ -n "$loginfailed" ];then
(echo "[!!!]日志中发现以下登录失败的情况:" && echo "$loginfailed") |  tee -a $danger_file  | $saveresult
(echo "[!!!]登录失败的IP及次数如下:" && grep "Failed password" /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c)  | $saveresult
(echo "[!!!]登录失败的用户及次数如下:" && grep "Failed password" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c)  | $saveresult
else
echo "[*]日志中未发现登录失败的情况" | $saveresult
fi
if [ -n "$systemlogin" ];then
(echo "[*]本机登录情况:" && echo "$systemlogin") | $saveresult
(echo "[*]本机登录账号及次数如下:" && more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c) | $saveresult
else
echo "[!!!]未发现在本机登录退出情况,请注意！！！" | $saveresult
fi

if [ -n "$newusers" ];then
(echo "[!!!]日志中发现新增用户:" && echo "$newusers") | tee -a $danger_file | $saveresult
(echo "[*]新增用户账号及次数如下:" && more /var/log/secure* | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
echo "[*]日志中未发现新增加用户" | $saveresult
fi
if [ -n "$newgoup" ];then
(echo "[!!!]日志中发现新增用户组:" && echo "$newgoup") | tee -a $danger_file | $saveresult
(echo "[*]新增用户组及次数如下:" && more /var/log/secure* | grep "new group" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
echo "[*]日志中未发现新增加用户组" | $saveresult
fi
else
echo -e " ${Tip}日志文件不存在,请分析是否被清除${RES}！" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

# ------------16.3message日志分析---------------
logfile2=(/var/log/messages*)
dns_history=$(less  $logfile2 | grep "using nameserver" | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
if [ -e "$logdir" ]  &&     [ -s  "$logfile2"    ]; then
(echo "[!!!]传输文件情况:" && echo "$zmodem") | tee -a $danger_file | $saveresult

if [ -n "$dns_history" ];then
(echo "[!!!]该服务器曾经使用以下DNS:" && echo "$dns_history") | tee -a $danger_file | $saveresult
else
echo "[*]未发现使用DNS服务器" | $saveresult
fi
else
echo "未发现/var/log/messages文件" | $saveresult
fi
printf "\n" | $saveresult
echo ------------16.4cron日志分析---------------
cron_download=$(more /var/log/cron* | grep "wget|curl")
if [ -n "$cron_download" ];then
(echo -e  "${Tip}定时下载情况: ${RES}" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
echo "[*]未发现定时下载情况" | $saveresult
fi
printf "\n" | $saveresult
cron_shell=$(more /var/log/cron* | grep -E "\.py$|\.sh$|\.pl$")
if [ -n "$cron_shell" ];then
(echo "[!!!]发现定时执行脚本:" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
echo "[*]未发现定时执行脚本" | $saveresult
fi
printf "\n" | $saveresult
# ------------16.5yum日志分析----------------------
logfile3=(/var/log/yum*)
yum_install=$(less  $logfile3 | grep Installed | awk '{print $NF}' | sort | uniq )
yum_scripts=$(less  $logfile3 | grep Installed | grep -E "(\.sh$\.py$|\.pl$)" | awk '{print $NF}' | sort | uniq)
yum_erased=$(less  $logfile3 | grep Erased)
hacker_tools=$(less  $logfile3 | awk -F: '{print $NF}' | awk -F '[-]' '{print $1}' | sort | uniq | grep -E "(^nc|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)")
if [ -e "$logdir" ]  &&     [ -s  "$logfile3"    ]; then
if [ -n "$yum_install" ];then
(echo  -e  "${Tip}曾使用yum下载以下软件:${RES} "  && echo "$yum_install") | $saveresult
else
echo "[*]未使用yum下载过软件" | $saveresult
fi
printf "\n" | $saveresult
if [ -n "$yum_scripts" ];then
(echo  -e  "${Tip}曾使用yum下载以下脚本文件:${RES} "  && echo "$yum_scripts") | $saveresult
else
echo "[*]未使用yum下载过脚本文件" | $saveresult
fi
printf "\n" | $saveresult
if [ -n "$yum_erased" ];then
(echo "[*]使用yum曾卸载以下软件:" && echo "$yum_erased")  | $saveresult
else
echo "[*]未使用yum卸载过软件" | $saveresult
fi
printf "\n" | $saveresult
if [ -n "$hacker_tools" ];then
(echo -e  "${Tip} 发现使用yum下载过以下可疑软件:${RES}" && echo "$hacker_tools") | tee -a $danger_file | $saveresult
else
echo "[*]未发现使用yum下载过可疑软件" | $saveresult
fi
printf "\n" | $saveresult

else
echo "/var/log/yum 文件不存在 " |  $saveresult
fi
# ------------16.7  其他日志分析----------------------
execs=("lastb lastlog last lsmod")
for ex in  $execs
do
if [ -n $ex ];then
(echo " $ex 日志如下:" &&  $ex) | $saveresult
else
echo " $ex 未发现错误登录日志" | $saveresult
fi
done

#echo ------------17 内核检查-------------------
lsmod=$(lsmod)
(echo "[*]内核信息如下:" && echo "$lsmod") | $saveresult
printf "\n" | $saveresult
echo "[17.2]正在检查可疑内核....." | $saveresult
danger_lsmod=$(lsmod | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
if [ -n "$danger_lsmod" ];then
(echo -e "${Tip} 发现可疑内核模块: ${RES}" && echo "$danger_lsmod") | tee -a $danger_file | $saveresult
else
echo "[*]未发现可疑内核模块" | $saveresult
fi
printf "\n" | $saveresult

# ------------18可疑软件-----------------
echo "[18.2]正在检查安装的可疑软件....." | $saveresult
danger_soft=$(rpm -qa  | awk -F- '{print $1}' | sort | uniq | grep -E "^(ncat|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$")
if [ -n "$danger_soft" ];then
(echo -e "${Tip}以下安装的软件可疑,需要人工分析:$RES"  && echo "$danger_soft") | tee -a $danger_file | $saveresult
else
echo "[*]未发现安装可疑软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20性能分析-----------------
# ------------20.1磁盘分析-----------------
echo "[*]磁盘使用情况如下:" && df -h  | $saveresult
printf "\n" | $saveresult
#使用超过70%告警
df=$(df -h | awk 'NR!=1{print $1,$5}' | awk -F% '{print $1}' | awk '{if ($2>70) print $1,$2}')
if [ -n "$df" ];then
(echo "[!!!]硬盘空间使用过高，请注意！！！" && echo "$df" ) | tee -a $danger_file | $saveresult
else
echo "[*]硬盘空间足够" | $saveresult
fi
printf "\n" | $saveresult
# ------------20.2CPU分析-----------------
(echo "CPU硬件信息如下:" && lscpu ) | $saveresult
printf "\n" | $saveresult
# ------------占用CPU TOP5 进程-----------------
(echo "占用CPU资源 top5：" && ps -aux | sort -nr -k 3 | head -5)  | $saveresult
printf "\n" | $saveresult
# ------------占用CPU较大进程-----------------
echo "正在检查占用CPU较大的进程....." | $saveresult
pscpu=$(ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=20) print $0}')
if [ -n "$pscpu" ];then
echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
echo "$pscpu" | tee -a 20.2.3_pscpu.txt | tee -a $danger_file | $saveresult
else
echo "[*]未发现进程占用资源超过20%" | $saveresult
fi
printf "\n" | $saveresult
# ------------20.3 内存分析-----------------
(echo "[*]内存信息如下:" && more /proc/meminfo) | $saveresult
(echo "[*]内存使用情况如下:" && free -m) | $saveresult
printf "\n" | $saveresult
# ------------20.3.2占用内存 top 5进程-----------------
echo "[20.2.2]正在检查占用内top5....." | $saveresult
(echo "[*]占用内存资源top5进程：" && ps -aux | sort -nr -k 4 | head -5) | $saveresult
printf "\n" | $saveresult
# ------------20.3.3占用内存较多进程-----------------
echo "[20.3.3]正在检查占用内存较多的进程....." | $saveresult
psmem=$(ps -aux | sort -nr -k 4 | head -5 | awk '{if($4>=2) print $0}')
if [ -n "$psmem" ];then
echo "[!!!]以下进程占用的内存超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
echo "$psmem" | tee -a $danger_file | $saveresult
else
echo "[*]未发现进程占用内存资源超过20%" | $saveresult
fi
printf "\n" | $saveresult

#------------21 网络挂载情况----------------------
share=$(exportfs)
if [ -n "$share" ];then
(echo -e "${Tip}网络共享情况如下:$RES" && echo "$share") | $saveresult
else
echo "[*]未发现网络共享" | $saveresult
fi
printf "\n" | $saveresult




echo   -e  "${Info}检查结束！！！$RES"
