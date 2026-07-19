package core

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// 获取网络IP（短超时，避免内网环境卡启动）
func GetNetIP() string {
	getUrl := "http://httpbin.org/ip"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(getUrl)
	if err != nil {
		ErrorLog("获取外网IP失败，err:%v\n", err)
		Myip = ""
		return Myip
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		ErrorLog("获取外网IP失败，err:%v\n", err)
		Myip = ""
		return Myip
	}
	b := regexp.MustCompile(`"origin":\s*"(.+?)"`).FindAllStringSubmatch(string(body), -1)
	if len(b) == 0 {
		ErrorLog("获取外网IP失败，err:未能从" + getUrl + "网站中获取到IP")
		Myip = ""
	} else {
		Myip = b[0][1]
	}
	return Myip
}

// 格式化文件大小
func FormatSize(size int64) string {
	const (
		B = 1 << (10 * iota)
		KB
		MB
		GB
		TB
		PB
	)
	switch {
	case size < KB:
		return fmt.Sprintf("%d B", size)
	case size < MB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	case size < GB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size < TB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size < PB:
		return fmt.Sprintf("%.2f TB", float64(size)/float64(TB))
	default:
		return fmt.Sprintf("%.2f PB", float64(size)/float64(PB))
	}
}

// 判断字符串是否在序列中
func Strinlist(str string, str_array []string) bool {
	for _, s := range str_array {
		if str == s {
			return true
		}
	}
	return false
}
