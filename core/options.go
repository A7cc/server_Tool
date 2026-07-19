package core

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 用户输入指令的解析
var (
	// 设置端口
	Port int
	// 是否只访问当前目录
	Only bool
	// 出网IP
	Myip string
	// 指定IP
	Customizeip string
	// 服务器模式类型
	Mode string
	// 输出日志
	Outfile string
	// 日志等级
	DebugLevel int
	// 版本
	version string = "1.3.0"
	// 设置验证
	Userauth string
	// 用户列表
	User_lists string
	// 设置是否写日志
	Logflag bool = false
	// 设置根目录
	RootDir string
	// 数据库路径
	DBPath string
	// FTP 模式 probe / real
	FtpMode string
	// 是否探测外网 IP（默认关闭，避免启动等待）
	ExtIP bool
)

// Version 返回版本号
func Version() string { return version }

// Flag 处理flag
func Flag() {
	// 打印图标
	tagPrint()
	// 设置端口
	flag.IntVar(&Port, "p", 10000, "自定义端口")
	// 指定IP
	flag.StringVar(&Customizeip, "hn", "", "设置服务器监听IP")
	flag.StringVar(&Userauth, "token", "", "设置userauth验证信息；未设置时禁止添加用户等写操作")
	flag.StringVar(&User_lists, "ul", "", "设置用户列表，逗号分割，例如：admin,demo")
	flag.StringVar(&Mode, "m", "http", "服务器类型：http / ftp")
	flag.StringVar(&Outfile, "outfile", "httpserver_log.txt", "保存日志文件")
	flag.IntVar(&DebugLevel, "debug", 0, "debug等级日志,0(Basic)/1(Error)/2(Debug)/3(Warn)")
	flag.BoolVar(&Logflag, "logflag", false, "是否写日志(默认不写)")
	flag.StringVar(&RootDir, "root", ".", "文件服务根目录（浏览/上传/真实FTP限制在此目录内）")
	flag.StringVar(&DBPath, "db", "", "SQLite数据库路径（默认 httpserver_db.db）")
	flag.StringVar(&FtpMode, "ftp-mode", "probe", "FTP模式：probe=协议探测(默认) / real=真实文件服务")
	flag.BoolVar(&ExtIP, "extip", false, "启动时，探测外网IP，获取外网IP（默认关闭，内网一般不需要）")
	// 解析命令行参数
	flag.Parse()
}

// ParseFlag 处理数据
func ParseFlag() error {
	if Port <= 0 || Port > 65535 {
		return errors.New("该端口不合规！")
	}
	absRoot, err := filepath.Abs(RootDir)
	if err != nil {
		return fmt.Errorf("解析根目录失败: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return fmt.Errorf("根目录不可用: %w", err)
	}
	if !info.IsDir() {
		return errors.New("根目录必须是文件夹")
	}
	RootDir = absRoot

	// 获取当前程序所在文件夹路径
	currentPath := getCurrentPath()
	if currentPath != "" && !filepath.IsAbs(Outfile) && !strings.Contains(Outfile, currentPath) {
		Outfile = filepath.Join(currentPath, Outfile)
	} else if !filepath.IsAbs(Outfile) {
		Outfile = filepath.Join(RootDir, Outfile)
	}

	FtpMode = strings.ToLower(strings.TrimSpace(FtpMode))
	if FtpMode != "probe" && FtpMode != "real" {
		return errors.New("ftp-mode 只能是 probe 或 real")
	}
	return nil
}

// 图标
func tagPrint() {
	fmt.Println(`                                         _________           .__   `)
	fmt.Println(`  ______ ______________  __ ___________  \__  ___/___   ____ |  |  `)
	fmt.Println(` /  ___// __ \_  __ \  \/ // __ \_  __ \   |  | /  _ \ /  _ \|  |  `)
	fmt.Println(` \___ \\  ___/|  | \/\   /\  ___/|  | \/   |  |(  <_> |  <_> )  |__`)
	fmt.Println(`/____  >\___  >__|    \_/  \___  >__|_/~~\_|__| \____/ \____/|_____\`)
	fmt.Println(`     \/     \/                 \/    server_Tool ver: ` + version)
	fmt.Println()
}

// 获取当前程序的路径
func getCurrentPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	// 获取程序所在目录
	return filepath.Dir(exePath)
}
