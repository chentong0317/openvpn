#!/bin/bash
echo $1 > "/root/aws_name.txt"
echo $(( $1 + 200 )) > "/root/aws_name.txt"


# 定义一个函数，用于检查软件包是否已安装
check_and_install() {
    PACKAGE=$1
    if dpkg -l | grep -q "^ii  $PACKAGE "; then
        echo "$PACKAGE 已安装，跳过安装。"
    else
        echo "$PACKAGE 未安装，正在安装..."
        sudo apt-get install -y $PACKAGE
        if [ $? -ne 0 ]; then
            echo "安装 $PACKAGE 失败，请检查网络连接或包管理器配置。"
            exit 1
        fi
    fi
}

# 判断是否需要更新软件包列表
update_package_list() {
    LAST_UPDATE_FILE="/var/lib/apt/periodic/update-success-stamp"
    if [ -f "$LAST_UPDATE_FILE" ]; then
        LAST_UPDATE=$(stat -c %Y "$LAST_UPDATE_FILE")
        CURRENT_TIME=$(date +%s)
        ELAPSED_TIME=$((CURRENT_TIME - LAST_UPDATE))
        if [ $ELAPSED_TIME -lt 86400 ]; then
            echo "软件包列表在24小时内已更新，跳过更新。"
            return
        fi
    fi
    echo "正在更新软件包列表..."
    sudo apt-get update
    if [ $? -ne 0 ]; then
        echo "软件包列表更新失败，请检查网络连接或软件源是否可用。"
        exit 1
    fi
}

# 更新软件包列表（带判断）
update_package_list

# 检查和安装所需软件包
PACKAGES=("tar" "gzip" "unzip" "net-tools" "cron" "wget")
for PACKAGE in "${PACKAGES[@]}"; do
    check_and_install $PACKAGE
done

echo "所有必需的软件包已处理完成！"

# 运行 v2ray.sh 脚本
echo "正在运行 v2ray.sh 脚本..."
bash <(wget -qO- -o- https://git.io/v2ray.sh)
if [ $? -eq 0 ]; then
    echo "v2ray.sh 脚本运行成功！"
else
    echo "v2ray.sh 脚本运行失败，请检查网络或脚本地址是否正确。"
    #exit 1
fi

# 运行 openvpn-install.sh 脚本
echo "正在运行 openvpn-install.sh 脚本..."
wget https://raw.githubusercontent.com/chentong0317/openvpn/refs/heads/master/openvpn-install.sh -O openvpn-install.sh && bash openvpn-install.sh
if [ $? -eq 0 ]; then
    echo "openvpn-install.sh 脚本运行成功！"
else
    echo "openvpn-install.sh 脚本运行失败，请检查网络或脚本地址是否正确。"
     #exit 1
fi

# 下载 OpenVPN 压缩包
echo "正在下载 OpenVPN 压缩包..."
wget https://github.com/chentong0317/openvpn/releases/download/v1.0.0/qingcheng.zip -O qingcheng.zip
if [ $? -eq 0 ]; then
    echo "qingcheng 压缩包下载成功！"
else
    echo "baihu 压缩包下载失败，请检查网络或链接地址是否正确。"
    #exit qingcheng
fi

# 解压 qingcheng 压缩包
echo "正在解压 OpenVPN 压缩包..."
unzip -o qingcheng.zip
if [ $? -eq 0 ]; then
    echo "OpenVPN 压缩包解压成功！"
else
    echo "OpenVPN 压缩包解压失败，请检查 unzip 是否已正确安装。"
    #exit 1
fi

# 删除目标目录（如果存在）
echo "正在清理目标目录..."
sudo rm -rf /etc/openvpn/server
sudo rm -rf /etc/v2ray/conf/*.json

# 复制新文件到目标目录
echo "正在复制文件到目标目录..."
sudo cp -r ./qingcheng/server /etc/openvpn/server
sudo cp -r ./qingcheng/v2ray/baihu.json /etc/v2ray/conf/baihu.json

sudo cp -r ./qingcheng/ipchange_aws_baihu.sh /root/ipchange_aws_baihu.sh
sudo cp -r ./qingcheng/ipchange_aws.sh /root/ipchange_aws.sh
sudo cp -r ./qingcheng/ipchange_aws2.sh /root/ipchange_aws2.sh
sudo chmod 777 /root/ipchange_aws_baihu.sh
sudo chmod 777 /root/ipchange_aws.sh
sudo chmod 777 /root/ipchange_aws2.sh



# 检查 cron 服务状态
echo "正在检查 cron 服务状态..."
if ! systemctl is-active --quiet cron; then
    echo "cron 服务未运行，正在启动..."
    sudo systemctl start cron
    if [ $? -ne 0 ]; then
        echo "无法启动 cron 服务，请检查系统日志。"
        exit 1
    fi
    echo "cron 服务已启动！"
else
    echo "cron 服务正在运行。"
fi

# 设置 cron 服务为开机启动
echo "确保 cron 服务已设置为开机启动..."
sudo systemctl enable cron
if [ $? -ne 0 ]; then
    echo "无法设置 cron 服务为开机启动，请检查系统配置。"
    exit 1
fi
echo "已成功设置 cron 服务为开机启动！"

#!/bin/bash

# 定义定时任务内容
CRON_JOB_1="*/2 * * * * sudo /root/ipchange_aws_baihu.sh"
CRON_JOB_2="0 */1 * * * sudo /root/ipchange_aws.sh"
CRON_JOB_3="*/1 * * * * sudo /root/ipchange_aws2.sh"

# 检查并添加定时任务到当前用户的 Crontab
add_cron_job () {
    local job="$1"
    # 检查任务是否已存在
    if crontab -l 2>/dev/null | grep -Fxq "$job"
    then
        echo "任务已存在: $job"
    else
        # 将任务追加到 crontab
        (crontab -l 2>/dev/null; echo "$job") | crontab -
        echo "任务已添加: $job"
    fi
}

# 添加每个定时任务
add_cron_job "$CRON_JOB_1"
add_cron_job "$CRON_JOB_2"
add_cron_job "$CRON_JOB_3"

echo "所有定时任务已处理完成。"
echo root:ct317319828 |sudo chpasswd root;
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
sudo reboot;

