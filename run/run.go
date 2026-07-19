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

	var lanIPs []string
	if core.Customizeip != "" {
		core.InfoLog("指定IP：")
		fmt.Println("  - " + core.Customizeip)
		lanIPs = append(lanIPs, core.Customizeip)
	} else {
		core.InfoLog("本机IP：")
		for _, ipval := range iplist {
			if ipNet, ok := ipval.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil && !strings.HasPrefix(ipNet.IP.String(), "169.") {
					ip := ipNet.IP.String()
					fmt.Println("  - " + ip)
					lanIPs = append(lanIPs, ip)
				}
			}
		}
		// 默认不探测外网 IP，避免无外网时启动卡住 ~3 秒
		if core.ExtIP {
			myip := core.GetNetIP()
			if myip != "" {
				fmt.Println("  - 外网 " + myip)
			}
		}
	}
	core.RightLog("您目前使用的服务为：" + strings.ToUpper(core.Mode))
	core.InfoLog("日志文件路径：" + core.Outfile)

	// 打开数据库（HTTP/FTP 都可用；FTP real 也会用 root）
	store := core.MustOpenStore(core.DBPath)
	if store != nil {
		defer store.Close()
	}

	switch strings.ToLower(core.Mode) {
	case "http":
		// 清空用户
		if err := store.ClearUsers(); err != nil {
			core.ErrorLog("清空数据库中的用户失败：%v", err)
		}
		// 写入用户
		var user_lists []string
		if strings.TrimSpace(core.User_lists) != "" {
			for _, u := range strings.Split(core.User_lists, ",") {
				u = strings.TrimSpace(u)
				if u != "" {
					user_lists = append(user_lists, u)
				}
			}
		}
		if store != nil {
			if err := store.EnsureUsers(user_lists); err != nil {
				core.ErrorLog("写入用户到数据库失败：%v", err)
			}
			dbUsers, err := store.ListUsers()
			if err != nil {
				core.ErrorLog("读取数据库用户失败：%v", err)
			} else {
				user_lists = core.MergeUserLists(user_lists, dbUsers)
			}
		}
		if len(user_lists) < 2 {
			core.WarnLog("未设置聊天室用户或聊天室用户少于 2 个，使用默认 demo,admin（建议用 -ul 指定）")
			user_lists = []string{"admin", "demo"}
			if store != nil {
				_ = store.EnsureUsers(user_lists)
			}
		}

		core.InfoLog("文件根目录：%s", core.RootDir)
		core.InfoLog("HTTP服务器端口为：%v", core.Port)
		host := ":" + strconv.Itoa(core.Port)
		if core.Customizeip != "" {
			host = core.Customizeip + host
		}
		// 访问地址说明（别人必须用局域网 IP，不能用 127.0.0.1）
		core.RightLog("浏览器请访问：")
		fmt.Printf("    http://127.0.0.1:%d/          （仅本机 Mac 自己）\n", core.Port)
		if len(lanIPs) == 0 {
			core.WarnLog("未发现局域网 IPv4，其他人可能无法访问；请检查 Wi‑Fi/有线是否已连接")
		}
		for _, ip := range lanIPs {
			fmt.Printf("    http://%s:%d/   （其他人请用这个）\n", ip, core.Port)
		}
		if strings.HasPrefix(host, "127.") || host == "localhost:"+strconv.Itoa(core.Port) {
			core.WarnLog("当前 -hn 只监听本机回环，局域网其他人无法访问；请去掉 -hn 或改为 0.0.0.0")
		}
		err = servertype.HttpRunServer(core.Userauth, host, user_lists, core.RootDir)
		if err != nil {
			core.ErrorLog(err.Error())
		}
	case "ftp":
		// FTP：若端口仍为默认 10000，则改用 21
		if core.Port == 10000 {
			core.Port = 21
		}
		core.InfoLog("FTP 模式：%s", core.FtpMode)
		core.InfoLog("FTP服务器端口为：%v（%v）", core.Port, core.FtpMode)
		if core.FtpMode == "real" {
			core.InfoLog("FTP 根目录：%s", core.RootDir)
		} else {
			core.WarnLog("当前为探测模式：仅模拟应答，无真实文件传输")
		}
		host := ":" + strconv.Itoa(core.Port)
		if core.Customizeip != "" {
			host = core.Customizeip + host
		}
		err = servertype.FtpRunServer(host, core.FtpMode, core.RootDir, core.Userauth)
		if err != nil {
			core.ErrorLog(err.Error())
		}
	default:
		core.ErrorLog("不存在该服务类型")
	}
}
