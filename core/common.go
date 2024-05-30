package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
)

// 获取网络IP
func GetNetIP() string {
	getUrl := "http://httpbin.org/ip"
	resp, err := http.Get(getUrl)
	if err != nil {
		ErrorLog("获取外网IP失败，err:%v\n", err)
		Myip = ""
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			ErrorLog("获取外网IP失败，err:%v\n", err)
			Myip = ""
		} else {
			b := regexp.MustCompile(`"origin":.+"(.+?)"`).FindAllStringSubmatch(string(body), -1)
			if len(b) == 0 {
				ErrorLog("获取外网IP失败，err:未能从" + getUrl + "网站中获取到IP")
			} else {
				Myip = b[0][1]
			}
		}
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
