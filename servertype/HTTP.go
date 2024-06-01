package servertype

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"server_Tool/core"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Dir string
type File interface {
	io.Closer
	io.Reader
	io.Seeker
	Readdir(count int) ([]fs.FileInfo, error)
	Stat() (fs.FileInfo, error)
}

type FileSystem interface {
	Open(name string) (File, error)
}

// 类型
type fileHandler struct {
	root FileSystem
}

// 用户信息
type UserInfo struct {
	ID       int             `json:"id"`
	UserName string          `json:"username"`
	Conn     *websocket.Conn `json:"conn"`
}

// 发送信息内容
type Message struct {
	ID          int      `json:"id"`
	UserName    string   `json:"username"`
	UserList    []string `json:"userlist"`
	Msgtype     int      `json:"msgtype"`
	Usernum     int      `json:"usernum"`
	MessageData string   `json:"messagedata"`
	Time        string   `json:"time,omitempty"`
}

var (
	// 设置auth
	auth string = ""
	// 存放用户数据列表
	users    = make(map[int]UserInfo)
	namelist = []string{}
	upgrader = websocket.Upgrader{
		// 在这里可以根据需要验证origin或其他HTTP头信息
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	// 保护连接和用户的锁
	mu sync.Mutex
)

// http服务
func HttpRunServer(userauth, port string, usernamelist []string) error {
	// 赋值用户列表
	core.InfoLog("可用用户：%v", usernamelist)
	namelist = usernamelist
	// 设置验证信息
	auth = userauth
	core.DebugLog("初始化路由")
	// 创建一个mux路由器
	router := http.NewServeMux()
	core.DebugLog("创建路由")
	// 设置主页，并应用日志中间件
	router.HandleFunc("/", pageIndex)
	// 设置显示文件列表
	router.Handle("/showfile/", authMiddleware(pageFileServer(Dir("./"))))
	// 设置上传路由
	router.Handle("/upload", authMiddleware(http.HandlerFunc(pageUpload)))
	if auth != "" {
		// 设置userauth
		router.HandleFunc("/setuserauth", setuserauth)
	}
	// 聊天室
	router.Handle("/wschatroom", authMiddleware(http.HandlerFunc(wschatroom)))
	router.Handle("/chatroomhome", authMiddleware(http.HandlerFunc(chatroomHome)))

	core.DebugLog("运行服务")
	// 设置端口和IP
	err := http.ListenAndServe(":"+port, router)
	if err != nil {
		return err
	}
	return nil
}

// 首页
func pageIndex(w http.ResponseWriter, r *http.Request) {
	core.DebugLog("显示首页")
	core.DebugLog("获取主机名")
	name, err := os.Hostname()
	if err != nil {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Root</a>`
	} else {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">` + name + `</a>`
	}
	html := `<!DOCTYPE html>
	<html>
	<head>
	<meta charset="utf-8">
	<title>Root</title>
	</head>
	<body>
	<div id="header">
	<table style="min-width: 500px;">
		<caption align="center">
		<div style="display: flex; justify-content: space-between; align-items: center;">
    		<div style="flex: 1; text-align: left;"><a href="/" style="font-weight: bold;">[Root]</a></div>
    		<div style="flex: 1; text-align: center;">` + name + `</div>
    		<div style="flex: 1; text-align: right;"><a href="../" style="font-weight: bold;">[Back]</a></div>
		</div>
		</caption>
		<tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
		<tr><td>&nbsp;</td></tr>
	</table>
	</div>`
	if auth != "" {
		html = html + `<div style="padding: 5px; margin-bottom: 10px;"><a href="/setuserauth" style="font-weight: bold; font-size: 20px; text-align: center; text-decoration: none;">0.设置userauth</a></div>`
	}

	html = html + `
	<div style="padding: 5px; margin-bottom: 10px;"><a href="/showfile" style="font-weight: bold; font-size: 20px; text-align: center; text-decoration: none;">1.文件下载</a></div>
	<div style="padding: 5px; margin-bottom: 10px;"><a href="/upload" style="font-weight: bold; font-size: 20px; text-align: center; text-decoration: none;">2.文件上传</a></div>
	<div style="padding: 5px; margin-bottom: 10px;"><a href="/chatroomhome" style="font-weight: bold; font-size: 20px; text-align: center; text-decoration: none;">3.简易聊天室</a></div>
	</body></html>
	`
	fmt.Fprintln(w, html)
	// 日志输出
	logging(200, nil, w, r)
}

// 设置http错误
func toHTTPError(err error) (msg string, httpStatus int) {
	if errors.Is(err, fs.ErrNotExist) {
		return "404 page not found", 404
	}
	if errors.Is(err, fs.ErrPermission) {
		return "403 Forbidden", 403
	}
	return "500 Internal Server Error", 500
}

// 日志中间件，用于记录请求信息，该日志主要是设置http的日志
func logging(code int, err error, w http.ResponseWriter, r *http.Request) {
	// 获取客户端IP地址
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	}
	switch {
	case code >= 100 && code < 300:
		fmt.Printf("%v [%v] - %v - \033[1;32m%v\033[0m - %v %v\n", core.INFO, time.Now().Format("2006-01-02 15:04:05"), clientIP, code, r.Method, r.URL.Path)
	case code >= 300 && code < 400:
		fmt.Printf("%v [%v] - %v - \033[0;38;5;214m%v\033[0m - %v %v\n", core.INFO, time.Now().Format("2006-01-02 15:04:05"), clientIP, code, r.Method, r.URL.Path)
	default:
		fmt.Printf("%v [%v] - %v - \033[1;31m%v\033[0m - %v %v\n", core.INFO, time.Now().Format("2006-01-02 15:04:05"), clientIP, code, r.Method, r.URL.Path)
	}
	// 设置错误信息
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		http.Error(w, err.Error(), code)
		core.ErrLog("%s", err.Error())
	}
}

// 中间件函数，用于验证用户身份
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth != "" {
			core.DebugLog("通过获取cookie中的Userauth进行验证")
			cookie1, err := r.Cookie("Userauth")
			if err != nil {
				logging(401, errors.New("您未设置 Userauth 值，请在主页设置"), w, r)
				return
			}
			if cookie1.Value != auth {
				logging(401, errors.New("您未设置 Userauth 值，请在主页设置"), w, r)
				return
			}
		}
		// 如果身份验证通过，继续执行下一个处理程序
		next.ServeHTTP(w, r)
	})
}

// 设置userauth
func setuserauth(w http.ResponseWriter, r *http.Request) {
	core.DebugLog("设置userauth")
	core.DebugLog("验证是否设置Userauth")
	if r.Method == "POST" && r.Header.Get("Userauth") != "" {
		http.SetCookie(w, &http.Cookie{Name: "Userauth", Value: r.Header.Get("Userauth")})
	}
	core.DebugLog("获取主机名")
	name, err := os.Hostname()
	if err != nil {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Root</a>`
	} else {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">` + name + `</a>`
	}
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
	<meta charset="utf-8">
	<title>Upload</title>
	</head>
	<body>
	<div id="header">
	  <table style="min-width: 500px;">
		<caption align="center">
		<div style="display: flex; justify-content: space-between; align-items: center;">
			<div style="flex: 1; text-align: left;"><a href="/" style="font-weight: bold;">[Root]</a></div>
			<div style="flex: 1; text-align: center;">` + name + `</div>
			<div style="flex: 1; text-align: right;"><a href="../" style="font-weight: bold;">[Back]</a></div>
		</div>
		</caption>
		<tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
		<tr><td>&nbsp;</td></tr>
		</table>
	  </div>
	  <div style="padding: 10px;">
	  <div style="margin-bottom: 20px;">
		<p style="font-size: 20px; font-weight:bold">set userauth: <input type="text" name="userauth" style="font-size: 20px; position: sticky; cursor: pointer; width: 130px;" value=""></p>
	  </div>
	  <button style="padding: 8px 20px; font-size: 16px; font-weight: bold; cursor: pointer;" id="setuserauth">Set</button>
	  </div>
		<script>
		const textInput = document.querySelector('input[type="text"]');
		const setUserauth = document.querySelector('#setuserauth');
		setUserauth.addEventListener('click', function() {		
		  fetch('/setuserauth', {
			method: 'POST',
			headers: {
				'Userauth': textInput.value
			}
		  })
		  .then(response => response.text())
		  .catch(error => {
			console.error('Error:', error);
			alert('设置userauth失败');
		  });
		});
		</script>
	</body>
	</html>`
	fmt.Fprintln(w, html)
	// 日志输出
	logging(200, nil, w, r)
}

// 文件上传
func pageUpload(w http.ResponseWriter, r *http.Request) {
	core.DebugLog("显示文件上传页面")
	if r.Method == "POST" {
		// 设置文件上传限制
		r.ParseMultipartForm(32 << 20)
		// 路径
		path := r.FormValue("save_path")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// 日志输出
			logging(500, err, w, r)
			return
		}
		// 文件
		files := r.MultipartForm.File["files[]"]
		// 上传的文件名
		filenamelist := ""
		for _, file := range files {
			filename := file.Filename
			if path[len(path)-1] != '/' {
				filename = path + "/" + filename
			} else {
				filename = path + filename
			}
			f, err := file.Open()
			if err != nil {
				// 日志输出
				logging(500, err, w, r)
				return
			}
			defer f.Close()
			t, err := os.Create(filename)
			if err != nil {
				// 日志输出
				logging(500, err, w, r)
				return
			}
			defer t.Close()
			if _, err := io.Copy(t, f); err != nil {
				// 日志输出
				logging(500, err, w, r)
				return
			}
			filenamelist += file.Filename + " "
			// 日志输出
			logging(200, nil, w, r)
			core.RightLog("Uploaded File %v success!", file.Filename)
		}
		fmt.Fprintln(w, filenamelist+" 上传成功!")
	} else {
		core.DebugLog("获取主机名")
		name, err := os.Hostname()
		if err != nil {
			name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Root</a>`
		} else {
			name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">` + name + `</a>`
		}
		html := `<!DOCTYPE html>
		<html lang="en">
		<head>
		<meta charset="utf-8">
		<title>Upload</title>
		</head>
		<body>
		<div id="header">
		  <table style="min-width: 500px;">
			<caption align="center">
			<div style="display: flex; justify-content: space-between; align-items: center;">
				<div style="flex: 1; text-align: left;"><a href="/" style="font-weight: bold;">[Root]</a></div>
				<div style="flex: 1; text-align: center;">` + name + `</div>
				<div style="flex: 1; text-align: right;"><a href="../" style="font-weight: bold;">[Back]</a></div>
			</div>
			</caption>
			<tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
			<tr><td>&nbsp;</td></tr>
			</table>
		  </div>
		  <div style="padding: 10px;">
		  <div style="margin-bottom: 20px;">
			<p style="font-size: 20px; font-weight:bold">Save Path: <input type="text" name="save_path" style="font-size: 20px; position: sticky; cursor: pointer; width: 130px;" value="./"></p>
			<button style="padding: 8px 20px; font-size: 16px; font-weight: bold; cursor: pointer;">Choose Files</button>
			<input type="file" style="font-size: 25px; position: absolute; left: 20px; opacity: 0; cursor: pointer; width: 140px;" name="files[]" multiple />
		  </div>
		  <div class="file-names" style="margin-bottom: 10px;"></div>
		  <button style="padding: 8px 20px; font-size: 16px; font-weight: bold; cursor: pointer;" id="upload-button">Upload</button>
		  <div class="uploaded-files" style="margin-top: 20px;"></div>
		  </div>
		<script>
		const textInput = document.querySelector('input[type="text"]');
		const fileInput = document.querySelector('input[type="file"]');
		const fileNames = document.querySelector('.file-names');
		const uploadButton = document.querySelector('#upload-button');
		const uploadedFiles = document.querySelector('.uploaded-files');
		
		fileInput.addEventListener('change', function() {
		  const files = this.files;
		  let names = '';
		  Array.from(files).forEach(file => {
			names += file.name + ', ';
		  });
		  fileNames.textContent = names.slice(0, -2);
		});
		
		uploadButton.addEventListener('click', function() {
		  const files = fileInput.files;
		  if (files.length === 0) {
			alert('Please choose at least one file.');
			return;
		  }
		
		  const formData = new FormData();
		  Array.from(files).forEach(file => {
			formData.append('files[]', file);
		  });
		  formData.append('save_path', textInput.value)
		
		  fetch('/upload', {
			method: 'POST',
			body: formData
		  })
		  .then(response => response.text())
		  .then(result => {
			uploadedFiles.innerHTML += '<div class="uploaded-file" style="background-color: #ecf0f1; padding: 10px; border-radius: 5px; margin-bottom: 10px;">' + result + '</div>';
			fileInput.value = '';
			fileNames.textContent = '';
		  })
		  .catch(error => {
			console.error('Error:', error);
			alert('An error occurred during file upload.');
		  });
		});
		</script>
		</body>
		</html>`
		fmt.Fprintln(w, html)
		// 日志输出
		logging(200, nil, w, r)
		return
	}
}

// 列出并显示文件
func pageFileServer(root FileSystem) http.Handler {
	core.DebugLog("显示文件下载页面")
	return &fileHandler{root}
}

// 打开路径设置路由
func (d Dir) Open(path string) (File, error) {
	dir := string(d)
	if dir == "" {
		dir = "./"
	}
	// 拼接路径
	fullName := filepath.Join(dir, path)
	f, err := os.Open(fullName)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// 入口方法
func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	core.DebugLog("过滤url的/showfile/内容")
	upath := r.URL.Path
	// 添加路由
	if strings.HasPrefix(upath, `/showfile/`) {
		upath = upath[9:]
	}
	serveFile(w, r, f.root, path.Clean(upath))
}

// 设置重定向
func localRedirect(w http.ResponseWriter, newPath string) {
	w.Header().Set("Location", newPath)
	w.WriteHeader(301)
}

// 文件显示核心方法
func serveFile(w http.ResponseWriter, r *http.Request, fs FileSystem, name string) {
	// 打开文件目录并读取信息
	f, err := fs.Open(name)
	if err != nil {
		msg, code := toHTTPError(err)
		logging(code, errors.New(msg), w, r)
		return
	}
	defer f.Close()
	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		logging(code, errors.New(msg), w, r)
		return
	}
	// 判断url后面是否有/，如果没有则重定向到末尾有/路由中
	url := r.URL.Path
	if d.IsDir() {
		if url[len(url)-1] != '/' {
			localRedirect(w, path.Base(url)+"/")
			return
		}
	} else {
		if url[len(url)-1] == '/' {
			localRedirect(w, "../"+path.Base(url))
			return
		}
	}

	// 判断d是否为文件夹，如果是则返回页面
	if d.IsDir() {
		// 显示文件
		dirList(w, r, f)
		return
	}
	// 文件下载
	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}

// 列出文件核心方法
func dirList(w http.ResponseWriter, r *http.Request, f File) {
	var err error
	// 头部内容
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	core.DebugLog("获取主机名")
	name, err := os.Hostname()
	if err != nil {
		name = `<a href="/showfile/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">ShowFile</a>`
	} else {
		name = `<a href="/showfile/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">` + name + `</a>`
	}
	fmt.Fprintf(w, `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ShowFile</title>
</head>
<body>
<table style="min-width: 500px;">
	<caption align="center">
	<div style="display: flex; justify-content: space-between; align-items: center;">
		<div style="flex: 1; text-align: left;"><a href="/" style="font-weight: bold;">[Root]</a></div>
		<div style="flex: 1; text-align: center;">`+name+`</div>
		<div style="flex: 1; text-align: right;"><a href="../" style="font-weight: bold;">[Back]</a></div>
	</div>
	</caption>
	<tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
	<tr><td>&nbsp;</td></tr>
	<tbody><tr>
		<th><a href="#" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Name</a></th>
		<th><a href="#" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Last-modified</a></th>
		<th><a href="#" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Size</a></th>
	</tr>
	<tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
<tr><td>&nbsp;</td></tr>`)
	core.DebugLog("获取路由的文件夹")
	d, _ := f.(fs.ReadDirFile)
	dirs, err := d.ReadDir(-1)
	if err != nil {
		logging(500, errors.New("error reading directory"), w, r)
		return
	}
	core.DebugLog("遍历路由的文件夹")
	// 遍历文件夹或文件名字
	for _, fileInfo := range dirs {
		val, err := fileInfo.Info()
		if err != nil {
			// 日志输出
			logging(500, err, w, r)
			continue
		}
		Url := url.URL{Path: val.Name()}
		if strings.Contains(val.Name(), "System Volume Information") {
			continue
		} else if strings.Contains(val.Name(), filepath.Base(os.Args[0])) {
			continue
		} else if val.IsDir() {
			fmt.Fprintf(w, "<tr><td><a style=\"font-weight: bold; text-decoration: none;\" href='%s'>%s</a></td><td>%v</td><td style=\"text-align: right\"><bold>-</bold></td></tr>", Url.String()+string(os.PathSeparator), val.Name()+string(os.PathSeparator), val.ModTime().Format("2006-01-02 15:04:05"))
		} else {
			fmt.Fprintf(w, "<tr><td><a style=\"text-decoration: none;\" href=\"%s\">%s</a></td><td style=\"color:#888;\">%v</td><td style=\"text-align: right\"><bold>%v</bold></td></tr>", Url.String(), val.Name(), val.ModTime().Format("2006-01-02 15:04:05"), core.FormatSize(val.Size()))
		}
	}
	fmt.Fprintln(w, "</tbody></table></body></html>")
	// 日志输出
	logging(200, nil, w, r)
}

// 发送信息
func broadcastMessage(msg Message, userlists map[int]UserInfo) {
	core.DebugLog("发送信息")
	mu.Lock()
	defer mu.Unlock()
	for _, u := range userlists {
		if err := u.Conn.WriteJSON(msg); err != nil {
			core.ErrorLog("向用户 %d: %v 发送消息时出错", u.ID, err)
			// todo：后面加的
			mu.Lock()
			u.Conn.Close()
			delete(userlists, u.ID)
			mu.Unlock()
		}
	}
}

// 连接路由
func wschatroom(w http.ResponseWriter, r *http.Request) {
	var errs error
	// 升级ws
	core.DebugLog("协议升级为ws")
	wsconn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		errs = err
		return
	}
	// todo:关闭连接，处理正确的退出
	defer func(wsconn *websocket.Conn) {
		core.DebugLog("出现错误，原因：%s", errs.Error())
		// 发送数据
		errmsg := Message{
			Msgtype:     4,
			MessageData: "出现错误，原因：" + errs.Error(),
			Time:        time.Now().Format("2006-01-02 15:04:05"),
		}
		// 群发信息
		broadcastMessage(errmsg, users)
		core.DebugLog("关闭 ws 连接")
		wsconn.Close()
	}(wsconn)
	core.DebugLog("获取初始化连接ws数据")
	// 从 wsconn 读取数据
	_, message, err := wsconn.ReadMessage()
	if err != nil {
		core.ErrorLog("出现错误：%s", err.Error())
		errs = errors.New("read:" + err.Error())
		return
	}
	core.DebugLog("将初始化连接wsconn数据反序列化失败")
	// 反序列化
	usertmp := &UserInfo{}
	err = json.Unmarshal(message, usertmp)
	if err != nil {
		core.ErrorLog("json 反序列化失败")
		// 序列化错误
		errs = errors.New("json 反序列化失败")
		return
	}
	core.DebugLog("验证是否在名字列表里")
	// 验证是否在名字列表里
	if !core.Strinlist(usertmp.UserName, namelist) {
		// 名字不对
		errs = errors.New(usertmp.UserName + " 不在可登录用户列表内")
		return
	}
	core.DebugLog("判断该用户是否已经登录")
	// 判断用户是否已经登录
	for _, s := range users {
		if s.UserName == usertmp.UserName {
			// 名字重复
			errs = errors.New(usertmp.UserName + " 登录名字重复")
			return
		}
	}
	core.DebugLog("初始化当前用户信息")
	// 创建用户
	mu.Lock()
	// 计算用户数量
	id := len(users) + 1
	// 创建用户
	user := UserInfo{
		ID:       id,
		UserName: usertmp.UserName,
		Conn:     wsconn,
	}
	users[id] = user
	mu.Unlock()
	name_list := []string{}
	for _, u := range users {
		name_list = append(name_list, u.UserName)
	}
	core.DebugLog("发送数据")
	// 发送数据
	welcomemsg := Message{
		ID:          user.ID,
		UserName:    user.UserName,
		Usernum:     len(users),
		Msgtype:     1,
		UserList:    name_list,
		MessageData: user.UserName,
		Time:        time.Now().Format("2006-01-02 15:04:05"),
	}
	core.InfoLog("新用户 %d %v 加入了", user.ID, user.UserName)
	// 群发信息
	broadcastMessage(welcomemsg, users)
	// 监听 ws 消息
	for {
		// 创建信息内容
		var msg Message
		core.DebugLog("获取读取的ws数据")
		err := wsconn.ReadJSON(&msg)
		if err != nil {
			core.ErrorLog("Error reading message from user %d: %v", user.ID, err)
			mu.Lock()
			delete(users, id)
			mu.Unlock()
			core.ErrorLog("用户 %d 已掉线\n", user.ID)
			errs = err
			break
		}
		// 信息等于空
		if msg.MessageData == "" {
			continue
		}
		core.InfoLog("用户发送的数据：%v", msg)
		switch {
		case msg.Msgtype == 3 && msg.UserName == user.UserName:
			core.DebugLog("发送类型为3的数据")
			msg.ID = user.ID
			msg.Time = time.Now().Format("2006-01-02 15:04:05")
			uinfo := map[int]UserInfo{}
			if len(msg.UserList) >= 1 {
				core.DebugLog("进入@用户类型处理")
				// 加入自己
				if !core.Strinlist(user.UserName, msg.UserList) {
					msg.UserList = append(msg.UserList, user.UserName)

				}
				for i, u := range users {
					if core.Strinlist(u.UserName, msg.UserList) {
						uinfo[i] = u
					}
				}
			} else {
				core.DebugLog("进入群发类型处理")
				uinfo = users
			}
			broadcastMessage(msg, uinfo)
		default:
			core.DebugLog("不在类型内的数据")
			msg.ID = 4
			msg.Time = time.Now().Format("2006-01-02 15:04:05")
			broadcastMessage(msg, users)
		}
	}
}

// 聊天页面
func chatroomHome(w http.ResponseWriter, r *http.Request) {
	core.DebugLog("显示聊天页")
	core.DebugLog("获取主机名")
	name, err := os.Hostname()
	if err != nil {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">Root</a>`
	} else {
		name = `<a href="/" style="color: black; font-weight: bold; text-align: center; text-decoration: none;">` + name + `</a>`
	}
	html := `<!DOCTYPE html>
	<html lang="zh-cn">
	<head>
	  <meta charset="utf-8">
	  <title>wschatroom</title>
	  <style>* {box-sizing: border-box;}</style>
	</head>
	<body style="width:500px; word-break:break-all;">
	  <div id="header">
		<table style="min-width: 500px;">
		  <caption align="center">
		  <div style="display: flex; justify-content: space-between; align-items: center;">
			  <div style="flex: 1; text-align: left;"><a href="/" style="font-weight: bold;">[Root]</a></div>
			  <div style="flex: 1; text-align: center;">` + name + `</div>
			  <div style="flex: 1; text-align: right;"><a href="../" style="font-weight: bold;">[Back]</a></div>
		  </div>
		  </caption>
		  <tr><td style="border-top:1px dashed #BBB;" colspan="5"></td></tr>
		  <tr><td>&nbsp;</td></tr>
		</table>
	<div class="row">
	  <div >
		<div style="border-top:1px solid #000000;margin-bottom: 20px; background-color: #fff; -webkit-box-shadow: 0 1px 1px rgba(0, 0, 0, .05); box-shadow: 0 1px 1px rgba(0, 0, 0, .05);border-color: #000000;">
		  <div class="panel-body" style="padding:0;">
			<div style="height:500px; margin: 0; padding:0; border-right:1px solid #000000;border-left:1px solid #000000; border-bottom:1px solid #000000; overflow-y:auto; position: relative; float: left; width: 20%">
			  <p style="text-align: center;"><span>CCU: </span><span id="user_num">0</span></p>
			  <hr>
			  <div id="user_list"></div>
			</div>
			<div style="padding:0; position: relative; min-height: 1px; float: left; width: 80%">
			  <div class="chat-list" style="height:399px; overflow-y:auto;border-right:1px solid #000000;" id="content">
			  </div>
			  <div style="height:100px; border-top:1px solid #000000;">
				<div style="width:80%; float:left; height:100px;">
				  <textarea id="msg" style="width:100%; height:100%; border: none; outline: none; padding: 10px; resize: none; font: inherit; overflow: auto; border-bottom:1px solid #000000;" onkeydown="confirm(event)"></textarea>
				</div>
				<div style="width:20%; float:left; text-align: center; line-height:100px; border-left:1px solid #000000; cursor: pointer;border-right:1px solid #000000;border-bottom:1px solid #000000;" onclick="send()">
				  发送
				</div>
			  </div>
			</div>
		  </div>
		</div>
	  </div>
	</div>
	<script>
	  // 设置名字
	  var username = prompt('请输入您分配到的用户名');
	  // websocket
	  var wsServer = 'ws://'+window.location.host+'/wschatroom';
	  var websocket = new WebSocket(wsServer);
	  // 点击发送
	  function send() {
		var msg = document.getElementById('msg').value.trim();
		// 正则匹配
		var regex = /@(.*?):/; 
		var matchstr;
		matchstr = msg.match(regex);
		var othername = [];
		if (matchstr != null && matchstr.length > 0) {
		  othername = matchstr[1].split(",");
		}
		var msgdata = {
		  //用户名
		  'username': username,
		  // @的用户
		  'userlist': othername,
		  // 发送信息
		  'messagedata': msg,
		  // 类型
		  'msgtype': 3,
		}
		// 生成json方便后台接收以及使用，发送
		websocket.send(JSON.stringify(msgdata));
		if (matchstr != null && matchstr.length > 0) {
		  // 然后清空输入框值
		  document.getElementById('msg').value = matchstr[0];
		}else{
		  // 然后清空输入框值
		  document.getElementById('msg').value = '';
		}
		
	  }
	  // 在输入框内按下回车键时发送消息
	  function confirm(event) {
		var key_num = event.keyCode;
		if (13 == key_num) {
			send();
		} else {
			return false;
		}
	  }
	  // 添加信息
	  function newMessage(msgData) {
		var chatlist = document.querySelector('.chat-list');
		var html = '<div class="col-xs-10 msg-item ">'
				+'<div style="padding:0;">'
				+'<div style="padding: 0px 5px; position: relative; min-height: 1px; float: left; width: 100%">'
				+'<div style="float:left;">'+msgData.username+'</div>'
				+'</div>'
				+'<div style="padding: 0px 5px; position: relative; min-height: 1px; float: left; width: 100%">'
				+'<div style="background: #d9edf7; line-height:25px; float:left; margin-left:10px; padding: 0px 5px;">'+msgData.message+'</div>'
				+'</div>'
				+'</div>'
				+'</div>';
		chatlist.insertAdjacentHTML('beforeend', html);
		chatlist.scrollTop = chatlist.scrollHeight;
	  }
	  // 用户列表操作
	  function editUser(user_name, name_list) {
		var user_list = document.getElementById("user_list");
		while(user_list.hasChildNodes()) {
		  user_list.removeChild(user_list.firstChild);
		}
		// 添加用户
		for (var index in name_list) {
		  var user = document.createElement("div");
		  user.innerHTML = name_list[index];
		  user_list.appendChild(user);
		}
		// 统计用户
		var user_num = document.getElementById("user_num");
		user_num.innerHTML = name_list.length;
		printprompt('系统消息: ' + user_name + ' 已上线');
		user_list.scrollTop = user_list.scrollHeight;
	  }
	  // 提示信息输出
	  function printprompt(promptmsg){
		var chatlist = document.querySelector('.chat-list');
		chatlist.insertAdjacentHTML('beforeend', '<p style="margin: 1 0; text-align: center;">'+promptmsg+'</p>');
		chatlist.scrollTop = chatlist.scrollHeight;
	  }
	  // 链接成功
	  websocket.onopen = function (evt) {
		printprompt("服务器已连接，开始聊天吧");
		var welcomemsg = {
		  //用户名
		  'username': username,
		}
		websocket.send(JSON.stringify(welcomemsg));
	  };
	  // 链接断开
	  websocket.onclose = function (evt) {
		printprompt("服务器已断开，请重新连接");
	  };
	  // 服务器异常
	  websocket.onerror = function (evt) {
		printprompt("服务器异常，请检查是否成功连接服务器");
	  };
	  // 收到服务器消息
	  websocket.onmessage = function (evt) {
		// 字符串格式化成json
		var msg = JSON.parse(evt.data); // 使用 JSON.parse 解析 JSON 数据
		switch (msg.msgtype) {
		  case 1:
			// 登录用户用户操作
			editUser(msg.messagedata, msg.userlist);
			break;
		  case 3:
			if (msg.username == username) {
			  // 自己发送的信息
			  var html = '<div class="col-xs-10 col-xs-offset-2 msg-item ">'
					  + '<div class="col-xs-11">'
					  + '<div style="padding: 0px 5px; position: relative; min-height: 1px; float: left; width: 100%">'
					  + '<div class="pull-right" style="float:left; float: right !important">' + msg.username + '</div>'
					  + '<div>'
					  + '<div style="padding: 0px 5px; position: relative; min-height: 1px; float: left; width: 100%">'
					  + '<div class="pull-right" style="background: #d9edf7; line-height:25px; float:left; margin-left:10px; padding: 0px 5px; float: right !important">' + msg.messagedata + '</div>'
					  + '</div>'
					  + '</div>';
			  document.querySelector('.chat-list').insertAdjacentHTML('beforeend', html);
			} else {
				var msgData = {
				  username: msg.username,
				  id: msg.id,
				  message: msg.messagedata,
				};
				newMessage(msgData);
			}
			// 接收到消息自动触底
			var div = document.getElementById("content");
			div.scrollTop = div.scrollHeight;
			break;
		  case 4:
			// 发送系统提示信息
			printprompt(msg.messagedata);
		}
	  };
	</script>
	
	</body>
	</html>`
	fmt.Fprintln(w, html)
	// 日志输出
	logging(200, nil, w, r)
}
