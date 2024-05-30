package run

import (
	"flag"
	"fmt"
	"net"
	"os"
	"server_Tool/core"
	"server_Tool/servertype"
	"strconv"
	"strings"
)

// 主程序
func Run() {
	// 处理flag
	core.Flag()
	// 初始化数据
	err := core.ParseFlag()
	if err != nil {
		fmt.Println(core.ERR, err)
		flag.Usage()
		return
	}

	iplist, err := net.InterfaceAddrs()
	if err != nil {
		core.ErrorLog("获取IP失败，err:%v\n", err)
		return
	}
	name, err := os.Hostname()
	if err != nil {
		core.ErrorLog("获取主机名失败，err:%v\n", err)
	}
	core.InfoLog("本机用户名：" + name)
	core.InfoLog("本机IP：")
	for _, ipval := range iplist {
		if ipNet, ok := ipval.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil && ipNet.IP.String()[0:3] != "169" {
				fmt.Println("  - " + ipNet.IP.String())
			}
		}
	}
	Myip := core.GetNetIP()
	if Myip != "" {
		fmt.Println("  - " + Myip)
	}
	// 提醒是否有userauth
	if core.Userauth == "" {
		core.WarnLog("您未设置 userauth 验证，可能存在安全风险")
	} else if len(core.Userauth) <= 15 {
		core.WarnLog("您设置的 userauth 验证长度较短，可能存在爆破安全风险")
	}
	core.RightLog("您目前使用的服务为：" + strings.ToUpper(core.Mode))
	switch strings.ToLower(core.Mode) {
	case "http":
		core.InfoLog("获取用户列表")
		var user_lists []string
		if strings.Contains(core.User_lists, ",") {
			user_lists = strings.Split(core.User_lists, ",")
		}
		if len(user_lists) == 0 {
			core.WarnLog("您未设置聊天室用户，将使用默认用户 demo,admin ，但是这样可能存在默认用户安全风险")
			user_lists = append(user_lists, []string{"admin", "demo"}...)
		}
		core.InfoLog("HTTP服务器端口为：%v", core.Port)
		err = servertype.HttpRunServer(core.Userauth, strconv.Itoa(core.Port), user_lists)
		if err != nil {
			core.ErrorLog(err.Error())
		}
	case "ftp":
		core.Port = 21
		core.InfoLog("FTP服务器端口为：%v", core.Port)
		err = servertype.FtpRunServer(strconv.Itoa(core.Port))
		if err != nil {
			core.ErrorLog(err.Error())
		}
	// case "dns":
	default:
		core.ErrorLog("不存在该服务类型")
	}
}
