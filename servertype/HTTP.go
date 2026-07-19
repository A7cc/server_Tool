package servertype

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"server_Tool/core"
	"server_Tool/servertype/web"
	"strings"
	"sync"
	"syscall"
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
	auth           string = ""
	rootDir        string = "."
	maxUploadBytes int64  = 200 << 20
	// 存放用户数据列表
	users    = make(map[int]UserInfo)
	namelist = []string{}
	upgrader = websocket.Upgrader{
		// 在这里可以根据需要验证origin或其他HTTP头信息
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			return strings.EqualFold(u.Host, r.Host)
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	// 保护连接和用户的锁
	mu sync.Mutex
)

func basePage(title string) web.PageData {
	host, err := os.Hostname()
	if err != nil {
		host = "server_Tool"
	}
	mu.Lock()
	usersCopy := append([]string(nil), namelist...)
	mu.Unlock()
	return web.PageData{
		Title:       title,
		Hostname:    host,
		AuthEnabled: auth != "",
		RootDir:     rootDir,
		Users:       usersCopy,
	}
}

// writeOpsAllowed 未设置 -token 时禁止写操作
func writeOpsAllowed() bool {
	return auth != ""
}

func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if writeOpsAllowed() {
		return true
	}
	writeError(403, errors.New("写操作已禁用：请使用 -token 启动并设置 userauth"), w, r)
	return false
}

// HttpRunServer 启动 HTTP 服务
func HttpRunServer(userauth, host string, usernamelist []string, fileRoot string) error {
	// 赋值用户列表
	core.InfoLog("可用用户：%v", usernamelist)
	namelist = usernamelist
	// 设置验证信息
	auth = userauth
	if fileRoot != "" {
		rootDir = fileRoot
	}
	// 预编译模板
	if _, err := web.Templates(); err != nil {
		return fmt.Errorf("加载内嵌网页失败: %w", err)
	}

	fileSrv := authMiddleware(pageFileServer(Dir(rootDir)))
	uploadH := authMiddleware(http.HandlerFunc(pageUpload))
	wsH := authMiddleware(http.HandlerFunc(wschatroom))
	chatH := authMiddleware(http.HandlerFunc(chatroomHome))
	setUserH := authMiddleware(http.HandlerFunc(setuser))
	staticH := http.StripPrefix("/static/", web.Static())

	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				core.ErrorLog("请求处理 panic: %v %s %s", rec, r.Method, r.URL.Path)
				http.Error(w, "internal error", 500)
			}
		}()
		p := r.URL.Path
		switch {
		case p == "/":
			pageIndex(w, r)
		case p == "/health":
			w.Write([]byte("ok"))
		case strings.HasPrefix(p, "/static/"):
			staticH.ServeHTTP(w, r)
		case p == "/upload":
			uploadH.ServeHTTP(w, r)
		case p == "/setuser":
			if auth == "" {
				writeError(404, errors.New("不能设置setuser（启动时未设置 -token）"), w, r)
				return
			}
			setUserH.ServeHTTP(w, r)
		case p == "/setuserauth":
			if auth == "" {
				writeError(404, errors.New("未启用 userauth（启动时未设置 -token）"), w, r)
				return
			}
			setuserauth(w, r)
		case p == "/wschatroom":
			wsH.ServeHTTP(w, r)
		case p == "/chatroomhome":
			chatH.ServeHTTP(w, r)
		case p == "/showfile" || strings.HasPrefix(p, "/showfile/"):
			fileSrv.ServeHTTP(w, r)
		default:
			writeError(404, errors.New("404 page not found"), w, r)
		}
	})

	srv := &http.Server{
		Addr:              host,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		// 提醒是否有userauth
		if auth == "" {
			core.WarnLog("写保护：加用户已禁用（未设置 -token）")
		} else if len(auth) <= 15 {
			core.WarnLog("您设置的 userauth 验证长度较短，可能存在爆破安全风险")
		}
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case sig := <-sigCh:
		core.WarnLog("收到信号 %v，正在优雅关闭…", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		mu.Lock()
		for id, u := range users {
			_ = u.Conn.Close()
			delete(users, id)
		}
		mu.Unlock()
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
			return err
		}
		core.RightLog("服务已关闭")
		return nil
	}
}

// 首页
func pageIndex(w http.ResponseWriter, r *http.Request) {
	if err := web.Render(w, "index.html", basePage("Root")); err != nil {
		core.ErrorLog("渲染首页失败: %v", err)
		accessLog(500, r)
		return
	}
	// 日志输出
	accessLog(200, r)
}

// 设置http错误
func toHTTPError(err error) (msg string, httpStatus int) {
	if errors.Is(err, fs.ErrNotExist) {
		return "404 page not found, err: " + err.Error(), 404
	}
	if errors.Is(err, fs.ErrPermission) {
		return "403 Forbidden, err: " + err.Error(), 403
	}
	return "500 Internal Server Error, err: " + err.Error(), 500
}

// 日志中间件，用于记录请求信息，该日志主要是设置http的日志
func accessLog(code int, r *http.Request) {
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	var color string
	switch {
	case code >= 100 && code < 300:
		color = "\033[1;32m"
	case code >= 300 && code < 400:
		color = "\033[0;38;5;214m"
	default:
		color = "\033[1;31m"
	}
	fmt.Printf("%v [%v] - %v - %s%v\033[0m - %v %v\n",
		core.INFO, time.Now().Format("2006-01-02 15:04:05"), clientIP, color, code, r.Method, r.URL.Path)
	if core.Logflag {
		core.PrintLog("[%v] - %v - %v - %v %v",
			time.Now().Format("2006-01-02 15:04:05"), clientIP, code, r.Method, r.URL.Path)
	}
}

func writeError(code int, err error, w http.ResponseWriter, r *http.Request) {
	accessLog(code, r)
	if err != nil {
		core.ErrLog("%s", err.Error())
		http.Error(w, err.Error(), code)
	} else {
		http.Error(w, http.StatusText(code), code)
	}
}

// 中间件函数，用于验证用户身份
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth != "" {
			cookie1, err := r.Cookie("Userauth")
			if err != nil || cookie1.Value != auth {
				writeError(401, errors.New("未授权：请先在主页设置正确的 Userauth"), w, r)
				return
			}
		}
		// 如果身份验证通过，继续执行下一个处理程序
		next.ServeHTTP(w, r)
	})
}

func setAuthCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "Userauth",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   8 * 3600,
	})
}

// 设置userauth
func setuserauth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		val := r.Header.Get("Userauth")
		if val == "" {
			_ = r.ParseForm()
			val = r.FormValue("userauth")
		}
		if val == "" {
			writeError(400, errors.New("Userauth 不能为空"), w, r)
			return
		}
		if auth != "" && val != auth {
			writeError(401, errors.New("Userauth 不正确"), w, r)
			return
		}
		setAuthCookie(w, val)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "ok")
		accessLog(200, r)
		return
	}
	_ = web.Render(w, "setuserauth.html", basePage("SetUserauth"))
	accessLog(200, r)
}

// 操作用户
func setuser(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method == "POST" {
		bodybt, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			writeError(400, errors.New("获取请求失败"), w, r)
			return
		}
		defer r.Body.Close()
		req := &struct {
			User   string `json:"user"`
			Action string `json:"action"` // add（默认）| delete
		}{}
		if err = json.Unmarshal(bodybt, req); err != nil {
			writeError(400, errors.New("反序列化失败"), w, r)
			return
		}
		req.User = strings.TrimSpace(req.User)
		req.Action = strings.ToLower(strings.TrimSpace(req.Action))
		if req.Action == "" {
			req.Action = "add"
		}
		if req.User == "" {
			writeError(400, errors.New("用户名不能为空"), w, r)
			return
		}
		// 安全性检测
		// 长度限制
		if len(req.User) > 10 {
			writeError(400, errors.New("您输入的名字过长"), w, r)
			return
		}
		for _, c := range req.User {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				writeError(400, errors.New("用户名仅允许字母数字下划线与短横线"), w, r)
				return
			}
		}

		switch req.Action {
		case "add":
			mu.Lock()
			exists := core.Strinlist(req.User, namelist)
			if !exists {
				namelist = append(namelist, req.User)
			}
			cur := append([]string(nil), namelist...)
			mu.Unlock()
			if exists {
				writeError(409, errors.New("输入的用户已存在"), w, r)
				return
			}
			if store := core.GetStore(); store != nil {
				if err := store.AddUser(req.User); err != nil {
					core.ErrorLog("持久化用户失败：%v", err)
				}
			}
			core.InfoLog("添加用户：%v", req.User)
			core.InfoLog("目前存在的用户：%v", cur)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, "User:"+req.User)
			accessLog(200, r)
			return

		case "delete":
			mu.Lock()
			idx := -1
			for i, n := range namelist {
				if n == req.User {
					idx = i
					break
				}
			}
			if idx < 0 {
				mu.Unlock()
				writeError(404, errors.New("用户不存在"), w, r)
				return
			}
			// 踢掉在线连接
			var kick []UserInfo
			for id, u := range users {
				if u.UserName == req.User {
					kick = append(kick, u)
					delete(users, id)
				}
			}
			namelist = append(namelist[:idx], namelist[idx+1:]...)
			cur := append([]string(nil), namelist...)
			online := onlineNameList()
			mu.Unlock()

			for _, u := range kick {
				writeWSError(u.Conn, "您的账号已被管理员删除，连接即将关闭")
				_ = u.Conn.Close()
			}
			// 通知其他人刷新列表
			if len(kick) > 0 {
				broadcastMessage(Message{
					Msgtype:     2,
					UserName:    req.User,
					Usernum:     len(online),
					UserList:    online,
					MessageData: req.User,
					Time:        time.Now().Format("2006-01-02 15:04:05"),
				}, copyUsers())
			}
			if store := core.GetStore(); store != nil {
				if err := store.DeleteUser(req.User); err != nil {
					core.ErrorLog("从数据库删除用户失败：%v", err)
				}
			}
			core.InfoLog("删除用户：%v", req.User)
			core.InfoLog("目前存在的用户：%v", cur)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, "deleted:"+req.User)
			accessLog(200, r)
			return

		default:
			writeError(400, errors.New("未知操作，action 应为 add 或 delete"), w, r)
			return
		}
	}
	_ = web.Render(w, "setuser.html", basePage("AddUser"))
	accessLog(200, r)
}

func safeJoin(rel string) (string, error) {
	if rel == "" || rel == "." {
		return rootDir, nil
	}
	rel = filepath.FromSlash(strings.TrimPrefix(filepath.ToSlash(rel), "/"))
	if filepath.IsAbs(rel) || (len(rel) >= 2 && rel[1] == ':') {
		return "", errors.New("不允许绝对路径")
	}
	full := filepath.Join(rootDir, rel)
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	sep := string(os.PathSeparator)
	if absFull != absRoot && !strings.HasPrefix(absFull, absRoot+sep) {
		return "", errors.New("路径越界，禁止访问根目录之外")
	}
	return absFull, nil
}

func cleanUploadName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("空文件名")
	}
	name = filepath.Base(filepath.FromSlash(name))
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return "", errors.New("非法文件名")
	}
	if deny_access_file(name) {
		return "", errors.New("禁止上传该文件名")
	}
	return name, nil
}

// 文件上传
func pageUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+1<<20)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeError(400, fmt.Errorf("解析上传表单失败: %w", err), w, r)
			return
		}
		savePath := r.FormValue("save_path")
		if savePath == "" {
			savePath = "."
		}
		dirAbs, err := safeJoin(savePath)
		if err != nil {
			writeError(400, err, w, r)
			return
		}
		st, err := os.Stat(dirAbs)
		if err != nil || !st.IsDir() {
			writeError(400, errors.New("保存路径不存在或不是目录"), w, r)
			return
		}
		if r.MultipartForm == nil || r.MultipartForm.File == nil {
			writeError(400, errors.New("未选择文件"), w, r)
			return
		}
		files := r.MultipartForm.File["files[]"]
		if len(files) == 0 {
			writeError(400, errors.New("未选择文件"), w, r)
			return
		}
		filenamelist := ""
		for _, file := range files {
			baseName, err := cleanUploadName(file.Filename)
			if err != nil {
				writeError(400, err, w, r)
				return
			}
			if file.Size > maxUploadBytes {
				writeError(400, fmt.Errorf("文件 %s 超过大小限制", baseName), w, r)
				return
			}
			destPath := filepath.Join(dirAbs, baseName)
			absDest, _ := filepath.Abs(destPath)
			absRoot, _ := filepath.Abs(rootDir)
			if absDest != absRoot && !strings.HasPrefix(absDest, absRoot+string(os.PathSeparator)) {
				writeError(400, errors.New("路径越界"), w, r)
				return
			}
			f, err := file.Open()
			if err != nil {
				writeError(500, err, w, r)
				return
			}
			t, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				f.Close()
				writeError(500, err, w, r)
				return
			}
			written, err := io.Copy(t, io.LimitReader(f, maxUploadBytes+1))
			f.Close()
			t.Close()
			if err != nil {
				writeError(500, err, w, r)
				return
			}
			if written > maxUploadBytes {
				_ = os.Remove(destPath)
				writeError(400, fmt.Errorf("文件 %s 超过大小限制", baseName), w, r)
				return
			}
			filenamelist += baseName + " "
			core.RightLog("Uploaded File %v success! -> %s", baseName, destPath)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, filenamelist+" 上传成功!")
		accessLog(200, r)
		return
	}
	_ = web.Render(w, "upload.html", basePage("Upload"))
	accessLog(200, r)
}

// 列出并显示文件
func pageFileServer(root FileSystem) http.Handler {
	return &fileHandler{root}
}

// 打开路径设置路由
func (d Dir) Open(name string) (File, error) {
	dir := string(d)
	if dir == "" {
		dir = rootDir
	}
	name = filepath.ToSlash(name)
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "."
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return nil, fs.ErrPermission
		}
	}
	cleaned := path.Clean("/" + name)
	if cleaned == "/" {
		name = "."
	} else {
		name = strings.TrimPrefix(cleaned, "/")
	}
	fullName := filepath.Join(dir, filepath.FromSlash(name))
	absFull, err := filepath.Abs(fullName)
	if err != nil {
		return nil, err
	}
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	realFull, err := filepath.EvalSymlinks(absFull)
	if err != nil {
		if absFull != absRoot && !strings.HasPrefix(absFull, absRoot+string(os.PathSeparator)) {
			return nil, fs.ErrPermission
		}
		f, err := os.Open(absFull)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		realRoot = absRoot
	}
	if realFull != realRoot && !strings.HasPrefix(realFull, realRoot+string(os.PathSeparator)) {
		return nil, fs.ErrPermission
	}
	f, err := os.Open(realFull)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// 入口方法
func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	const prefix = "/showfile"
	if upath == prefix {
		localRedirect(w, prefix+"/")
		return
	}
	if !strings.HasPrefix(upath, prefix+"/") {
		writeError(404, errors.New("not found"), w, r)
		return
	}
	rel := strings.TrimPrefix(upath, prefix+"/")
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." || seg == "%2e%2e" || strings.EqualFold(seg, "%2e%2e") {
			writeError(403, errors.New("非法路径"), w, r)
			return
		}
	}
	// 解码后再查 ..
	if dec, err := url.PathUnescape(rel); err == nil {
		for _, seg := range strings.Split(dec, "/") {
			if seg == ".." {
				writeError(403, errors.New("非法路径"), w, r)
				return
			}
		}
		rel = dec
	}
	cleaned := path.Clean("/" + rel)
	if cleaned == "/" {
		cleaned = "."
	} else {
		cleaned = strings.TrimPrefix(cleaned, "/")
	}
	serveFile(w, r, f.root, cleaned)
}

// 设置重定向
func localRedirect(w http.ResponseWriter, newPath string) {
	if strings.HasPrefix(newPath, "/") && !strings.HasPrefix(newPath, "/showfile") {
		newPath = path.Join("/showfile", newPath)
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}

// 文件显示核心方法
func serveFile(w http.ResponseWriter, r *http.Request, fsys FileSystem, name string) {
	f, err := fsys.Open(name)
	if err != nil {
		msg, code := toHTTPError(err)
		writeError(code, errors.New(msg), w, r)
		return
	}
	defer f.Close()
	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		writeError(code, errors.New(msg), w, r)
		return
	}
	reqPath := r.URL.Path
	if d.IsDir() {
		if !strings.HasSuffix(reqPath, "/") {
			localRedirect(w, reqPath+"/")
			return
		}
		dirList(w, r, f, name)
		return
	}
	if strings.HasSuffix(reqPath, "/") {
		localRedirect(w, strings.TrimSuffix(reqPath, "/"))
		return
	}
	if deny_access_file(d.Name()) {
		writeError(403, errors.New("禁止下载该文件"), w, r)
		return
	}
	accessLog(200, r)
	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}

// 列出文件核心方法
func dirList(w http.ResponseWriter, r *http.Request, f File, rel string) {
	rd, ok := f.(fs.ReadDirFile)
	if !ok {
		writeError(500, errors.New("error reading directory"), w, r)
		return
	}
	dirs, err := rd.ReadDir(-1)
	if err != nil {
		writeError(500, errors.New("error reading directory"), w, r)
		return
	}
	data := basePage("ShowFile")
	if rel == "." || rel == "" {
		data.RelPath = "/"
	} else {
		data.RelPath = "/" + filepath.ToSlash(rel)
	}
	// parent link
	if rel != "." && rel != "" && rel != "/" {
		parent := path.Dir("/" + filepath.ToSlash(rel))
		if parent == "/" {
			data.Parent = "/showfile/"
		} else {
			data.Parent = path.Join("/showfile", parent) + "/"
		}
	}
	for _, fileInfo := range dirs {
		val, err := fileInfo.Info()
		if err != nil {
			continue
		}
		if deny_access_file(val.Name()) {
			continue
		}
		u := url.URL{Path: val.Name()}
		ent := web.FileEntry{
			Name:    val.Name(),
			URL:     u.String(),
			IsDir:   val.IsDir(),
			ModTime: val.ModTime().Format("2006-01-02 15:04:05"),
		}
		if val.IsDir() {
			ent.URL = u.String() + "/"
		} else {
			ent.Size = core.FormatSize(val.Size())
		}
		data.Entries = append(data.Entries, ent)
	}
	_ = web.Render(w, "files.html", data)
	accessLog(200, r)
}

// 发送信息
func broadcastMessage(msg Message, targets map[int]UserInfo) {
	mu.Lock()
	defer mu.Unlock()
	ids := make([]int, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	var failed []int
	for _, id := range ids {
		u, ok := targets[id]
		if !ok || u.Conn == nil {
			continue
		}
		if err := u.Conn.WriteJSON(msg); err != nil {
			core.ErrorLog("向用户 %d: %v 发送消息时出错", u.ID, err)
			failed = append(failed, id)
		}
	}
	for _, id := range failed {
		if u, ok := users[id]; ok {
			_ = u.Conn.Close()
			delete(users, id)
		}
	}
}

func onlineNameList() []string {
	nameList := make([]string, 0, len(users))
	for _, u := range users {
		nameList = append(nameList, u.UserName)
	}
	return nameList
}

func nextUserID() int {
	maxID := 0
	for id := range users {
		if id > maxID {
			maxID = id
		}
	}
	return maxID + 1
}

func writeWSError(conn *websocket.Conn, text string) {
	if conn == nil {
		return
	}
	_ = conn.WriteJSON(Message{
		Msgtype:     4,
		MessageData: text,
		Time:        time.Now().Format("2006-01-02 15:04:05"),
	})
}

// 连接路由
func wschatroom(w http.ResponseWriter, r *http.Request) {
	wsconn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		core.ErrorLog("WebSocket 升级失败：%v", err)
		return
	}
	var (
		userID     int
		userName   string
		registered bool
	)
	defer func() {
		_ = wsconn.Close()
		if !registered {
			return
		}
		mu.Lock()
		delete(users, userID)
		nameList := onlineNameList()
		mu.Unlock()
		core.InfoLog("用户 %d %s 已离开", userID, userName)
		broadcastMessage(Message{
			Msgtype:     2,
			UserName:    userName,
			Usernum:     len(nameList),
			UserList:    nameList,
			MessageData: userName,
			Time:        time.Now().Format("2006-01-02 15:04:05"),
		}, copyUsers())
	}()

	_, message, err := wsconn.ReadMessage()
	if err != nil {
		writeWSError(wsconn, "读取登录信息失败")
		return
	}
	usertmp := &UserInfo{}
	if err = json.Unmarshal(message, usertmp); err != nil {
		writeWSError(wsconn, "登录数据格式错误")
		return
	}
	usertmp.UserName = strings.TrimSpace(usertmp.UserName)
	if usertmp.UserName == "" {
		writeWSError(wsconn, "用户名不能为空")
		return
	}
	if !core.Strinlist(usertmp.UserName, namelist) {
		writeWSError(wsconn, usertmp.UserName+" 不在可登录用户列表内")
		return
	}

	mu.Lock()
	for _, s := range users {
		if s.UserName == usertmp.UserName {
			mu.Unlock()
			writeWSError(wsconn, usertmp.UserName+" 已在线，请勿重复登录")
			return
		}
	}
	userID = nextUserID()
	userName = usertmp.UserName
	user := UserInfo{ID: userID, UserName: userName, Conn: wsconn}
	users[userID] = user
	nameList := onlineNameList()
	registered = true
	mu.Unlock()

	core.InfoLog("新用户 %d %v 加入了", user.ID, user.UserName)
	broadcastMessage(Message{
		ID:          user.ID,
		UserName:    user.UserName,
		Usernum:     len(nameList),
		Msgtype:     1,
		UserList:    nameList,
		MessageData: user.UserName,
		Time:        time.Now().Format("2006-01-02 15:04:05"),
	}, copyUsers())

	// 推送历史消息：仅群发 + 与当前用户相关的私聊（@ 目标含本人）
	if store := core.GetStore(); store != nil {
		if hist, err := store.RecentMessagesForUser(userName, 50); err == nil {
			for _, m := range hist {
				_ = wsconn.WriteJSON(Message{
					UserName:    m.UserName,
					Msgtype:     5,
					MessageData: m.Data,
					Time:        m.Time,
				})
			}
		}
	}

	for {
		var msg Message
		if err := wsconn.ReadJSON(&msg); err != nil {
			core.InfoLog("用户 %d %s 连接关闭：%v", user.ID, user.UserName, err)
			return
		}
		if strings.TrimSpace(msg.MessageData) == "" {
			continue
		}
		if msg.UserName != "" && msg.UserName != user.UserName {
			core.WarnLog("用户 %s 试图冒用 %s 发言，已忽略", user.UserName, msg.UserName)
			continue
		}
		msg.UserName = user.UserName
		msg.ID = user.ID
		msg.Time = time.Now().Format("2006-01-02 15:04:05")
		core.InfoLog("用户发送的数据：%v", msg)

		switch {
		case msg.Msgtype == 3:
			var targets map[int]UserInfo
			targetsStr := ""
			if len(msg.UserList) >= 1 {
				if !core.Strinlist(user.UserName, msg.UserList) {
					msg.UserList = append(msg.UserList, user.UserName)
				}
				targetsStr = strings.Join(msg.UserList, ",")
				targets = make(map[int]UserInfo)
				mu.Lock()
				for i, u := range users {
					if core.Strinlist(u.UserName, msg.UserList) {
						targets[i] = u
					}
				}
				mu.Unlock()
			} else {
				targets = copyUsers()
			}
			if store := core.GetStore(); store != nil {
				_ = store.SaveMessage(msg.UserName, msg.Msgtype, msg.MessageData, targetsStr)
			}
			broadcastMessage(msg, targets)
		default:
			msg.Msgtype = 4
			broadcastMessage(msg, copyUsers())
		}
	}
}

func copyUsers() map[int]UserInfo {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[int]UserInfo, len(users))
	for i, u := range users {
		out[i] = u
	}
	return out
}

// 聊天页面
func chatroomHome(w http.ResponseWriter, r *http.Request) {
	_ = web.Render(w, "chatroom.html", basePage("WsChatRoom"))
	accessLog(200, r)
}

// 不允许访问文件
func deny_access_file(filename string) bool {
	base := filepath.Base(filename)
	denyfiles := []string{
		"System Volume Information",
		"httpserver_db.db",
		filepath.Base(core.Outfile),
		"httpserver_log.txt",
	}
	for _, df := range denyfiles {
		if df == "" {
			continue
		}
		if strings.EqualFold(base, filepath.Base(df)) {
			return true
		}
	}
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		return true
	}
	return false
}
