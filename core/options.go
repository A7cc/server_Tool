package core

import (
	"errors"
	"flag"
	"fmt"
)

// 用户输入指令的解析
var (
	// 设置端口
	Port int
	// 是否只访问当前目录
	Only bool
	// 出网IP
	Myip string
	// 服务器模式类型
	Mode string
	// 输出日志
	outfile string
	// 日志等级
	debugLevel int
	// 版本
	version string = "1.1.0"
	// 设置验证
	Userauth string
	// 用户列表
	User_lists string
)

// 处理flag
func Flag() {
	// 打印图标
	tagPrint()
	// 设置端口
	flag.IntVar(&Port, "p", 10000, "自定义端口")
	flag.StringVar(&Userauth, "au", "", "设置userauth验证信息，减少未授权风险")
	flag.StringVar(&User_lists, "ul", "", "设置用户列表，通过英文的逗号分割，例如：admin,demo")
	flag.StringVar(&Mode, "m", "HTTP", "设置开启的服务器类型，ftp/http")
	flag.StringVar(&outfile, "outfile", "log.txt", "保存日志文件")
	flag.IntVar(&debugLevel, "debug", 0, "debug等级日志,0(Basic)/1(Error)/3(Warn)/4(Debug)")
	// 解析命令行参数
	flag.Parse()
}

// 处理数据
func ParseFlag() error {
	if Port <= 0 || Port > 65535 {
		return errors.New("该端口不合规！")
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
