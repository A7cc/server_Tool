package servertype

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"server_Tool/core"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FtpRunServer 启动 FTP。mode: probe | real
func FtpRunServer(host, mode, root, userauth string) error {
	ln, err := net.Listen("tcp", host)
	if err != nil {
		return err
	}
	defer ln.Close()

	// 简易 accept 循环；Ctrl+C 时进程退出即可（与 HTTP 优雅关闭不同，FTP 保持简单）
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if mode == "real" {
			go handleRealFTP(conn, root, userauth)
		} else {
			go handleProbeFTP(conn)
		}
	}
}

func ftpSend(w *bufio.Writer, codeMsg string) {
	_, _ = w.WriteString(codeMsg + "\r\n")
	_ = w.Flush()
}

// ---------- probe：协议探测 / 蜜罐应答 ----------
func handleProbeFTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	ftpSend(w, "220 server_Tool FTP probe mode (no real file transfer)")
	core.InfoLog("FTP probe 连接：%s", conn.RemoteAddr())

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.Fields(strings.TrimSpace(line))
		if len(cmd) == 0 {
			continue
		}
		core.DebugLog("FTP probe << %s", strings.TrimSpace(line))
		switch strings.ToUpper(cmd[0]) {
		case "USER":
			ftpSend(w, "331 User name okay, need password")
		case "PASS":
			ftpSend(w, "230 User logged in, proceed (probe mode)")
		case "SYST":
			ftpSend(w, "215 UNIX Type: L8")
		case "FEAT":
			ftpSend(w, "211-Features:")
			ftpSend(w, "211 End")
		case "PWD", "XPWD":
			ftpSend(w, `257 "/" is current directory`)
		case "CWD", "XCWD":
			ftpSend(w, "250 Directory changed successfully")
		case "TYPE":
			ftpSend(w, "200 Type set")
		case "PASV":
			// 探测模式：声明不支持数据连接
			ftpSend(w, "502 PASV not available in probe mode")
		case "PORT":
			ftpSend(w, "502 PORT not available in probe mode")
		case "LIST", "NLST", "RETR", "STOR", "SIZE", "MDTM":
			ftpSend(w, "550 Probe mode: no real filesystem")
		case "NOOP":
			ftpSend(w, "200 NOOP ok")
		case "QUIT":
			ftpSend(w, "221 Goodbye")
			return
		default:
			ftpSend(w, "500 Unknown command")
		}
	}
}

// ---------- real：受限根目录文件服务 ----------
type ftpSession struct {
	root     string
	cwd      string // 相对 root 的路径，用 /
	user     string
	loggedIn bool
	auth     string
	dataHost string
	dataPort int
	passive  net.Listener
	mu       sync.Mutex
}

func handleRealFTP(conn net.Conn, root, userauth string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	s := &ftpSession{root: root, cwd: "/", auth: userauth}
	ftpSend(w, "220 server_Tool FTP real mode")
	core.InfoLog("FTP real 连接：%s root=%s", conn.RemoteAddr(), root)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			s.closePassive()
			return
		}
		raw := strings.TrimSpace(line)
		cmd := strings.Fields(raw)
		if len(cmd) == 0 {
			continue
		}
		op := strings.ToUpper(cmd[0])
		arg := ""
		if len(cmd) > 1 {
			arg = strings.Join(cmd[1:], " ")
		}
		core.DebugLog("FTP real << %s", raw)

		switch op {
		case "USER":
			s.user = arg
			ftpSend(w, "331 Password required")
		case "PASS":
			// 若设置了 -token，密码必须匹配；未设置则任意密码可登录（仍限制 root）
			if s.auth != "" && arg != s.auth {
				s.loggedIn = false
				ftpSend(w, "530 Login incorrect")
				continue
			}
			s.loggedIn = true
			ftpSend(w, "230 Login successful")
		case "SYST":
			ftpSend(w, "215 UNIX Type: L8")
		case "FEAT":
			ftpSend(w, "211-Features:")
			ftpSend(w, " PASV")
			ftpSend(w, " SIZE")
			ftpSend(w, " UTF8")
			ftpSend(w, "211 End")
		case "OPTS":
			ftpSend(w, "200 OK")
		case "PWD", "XPWD":
			if !s.requireLogin(w) {
				continue
			}
			ftpSend(w, fmt.Sprintf(`257 "%s" is current directory`, s.cwd))
		case "CWD", "XCWD":
			if !s.requireLogin(w) {
				continue
			}
			if err := s.changeDir(arg); err != nil {
				ftpSend(w, "550 "+err.Error())
			} else {
				ftpSend(w, "250 Directory changed")
			}
		case "CDUP":
			if !s.requireLogin(w) {
				continue
			}
			_ = s.changeDir("..")
			ftpSend(w, "250 Directory changed")
		case "TYPE":
			ftpSend(w, "200 Type set to I")
		case "PASV":
			if !s.requireLogin(w) {
				continue
			}
			if err := s.startPassive(conn); err != nil {
				ftpSend(w, "425 Cannot open passive connection")
				continue
			}
			// 使用控制连接本地 IP
			host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() == nil {
				ip = net.IPv4(127, 0, 0, 1)
			}
			v4 := ip.To4()
			p := s.dataPort
			ftpSend(w, fmt.Sprintf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
				v4[0], v4[1], v4[2], v4[3], p>>8, p&0xff))
		case "PORT":
			if !s.requireLogin(w) {
				continue
			}
			if err := s.parsePORT(arg); err != nil {
				ftpSend(w, "501 Bad PORT")
				continue
			}
			ftpSend(w, "200 PORT command successful")
		case "LIST", "NLST":
			if !s.requireLogin(w) {
				continue
			}
			s.doList(w, op == "NLST", arg)
		case "SIZE":
			if !s.requireLogin(w) {
				continue
			}
			path, err := s.resolve(arg)
			if err != nil {
				ftpSend(w, "550 "+err.Error())
				continue
			}
			st, err := os.Stat(path)
			if err != nil || st.IsDir() {
				ftpSend(w, "550 Not a file")
				continue
			}
			ftpSend(w, "213 "+strconv.FormatInt(st.Size(), 10))
		case "RETR":
			if !s.requireLogin(w) {
				continue
			}
			s.doRetr(w, arg)
		case "STOR":
			if !s.requireLogin(w) {
				continue
			}
			if s.auth == "" {
				ftpSend(w, "550 Write disabled: server started without -token")
				continue
			}
			s.doStor(w, arg)
		case "NOOP":
			ftpSend(w, "200 NOOP ok")
		case "QUIT":
			ftpSend(w, "221 Goodbye")
			s.closePassive()
			return
		default:
			ftpSend(w, "502 Command not implemented")
		}
	}
}

func (s *ftpSession) requireLogin(w *bufio.Writer) bool {
	if !s.loggedIn {
		ftpSend(w, "530 Please login")
		return false
	}
	return true
}

func (s *ftpSession) closePassive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passive != nil {
		_ = s.passive.Close()
		s.passive = nil
	}
}

func (s *ftpSession) startPassive(ctrl net.Conn) error {
	s.closePassive()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	s.mu.Lock()
	s.passive = ln
	s.dataPort = p
	s.dataHost = ""
	s.mu.Unlock()
	return nil
}

func (s *ftpSession) parsePORT(arg string) error {
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		return fmt.Errorf("bad port")
	}
	nums := make([]int, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			return fmt.Errorf("bad port")
		}
		nums[i] = n
	}
	s.mu.Lock()
	s.dataHost = fmt.Sprintf("%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3])
	s.dataPort = nums[4]*256 + nums[5]
	if s.passive != nil {
		_ = s.passive.Close()
		s.passive = nil
	}
	s.mu.Unlock()
	return nil
}

func (s *ftpSession) openData() (net.Conn, error) {
	s.mu.Lock()
	passive := s.passive
	host, port := s.dataHost, s.dataPort
	s.mu.Unlock()
	if passive != nil {
		_ = passive.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
		c, err := passive.Accept()
		s.closePassive()
		return c, err
	}
	if host == "" || port == 0 {
		return nil, fmt.Errorf("no data connection")
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 20*time.Second)
}

func (s *ftpSession) resolve(rel string) (string, error) {
	// 组合 cwd + rel
	p := rel
	if p == "" {
		p = s.cwd
	} else if !strings.HasPrefix(p, "/") {
		if s.cwd == "/" {
			p = "/" + p
		} else {
			p = s.cwd + "/" + p
		}
	}
	p = filepath.ToSlash(pathClean(p))
	if p == "" {
		p = "/"
	}
	// 映射到本地
	localRel := strings.TrimPrefix(p, "/")
	full := filepath.Join(s.root, filepath.FromSlash(localRel))
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(s.root)
	if err != nil {
		return "", err
	}
	if absFull != absRoot && !strings.HasPrefix(absFull, absRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path out of root")
	}
	// symlink 检查
	if st, err := os.Lstat(absFull); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			real, err := filepath.EvalSymlinks(absFull)
			if err != nil {
				return "", fmt.Errorf("invalid symlink")
			}
			if real != absRoot && !strings.HasPrefix(real, absRoot+string(os.PathSeparator)) {
				return "", fmt.Errorf("symlink out of root")
			}
			return real, nil
		}
	}
	return absFull, nil
}

func pathClean(p string) string {
	parts := strings.Split(p, "/")
	var stack []string
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, part)
	}
	return "/" + strings.Join(stack, "/")
}

func (s *ftpSession) changeDir(arg string) error {
	path, err := s.resolve(arg)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("not a directory")
	}
	// 计算相对 cwd
	absRoot, _ := filepath.Abs(s.root)
	rel, err := filepath.Rel(absRoot, path)
	if err != nil {
		return err
	}
	if rel == "." {
		s.cwd = "/"
	} else {
		s.cwd = "/" + filepath.ToSlash(rel)
	}
	return nil
}

func (s *ftpSession) doList(w *bufio.Writer, nlst bool, arg string) {
	path, err := s.resolve(arg)
	if err != nil {
		ftpSend(w, "550 "+err.Error())
		return
	}
	ftpSend(w, "150 Opening data connection")
	dc, err := s.openData()
	if err != nil {
		ftpSend(w, "425 Can't open data connection")
		return
	}
	defer dc.Close()
	entries, err := os.ReadDir(path)
	if err != nil {
		// 可能是文件
		st, e2 := os.Stat(path)
		if e2 != nil {
			ftpSend(w, "550 "+err.Error())
			return
		}
		line := formatListLine(st, filepath.Base(path), nlst)
		_, _ = io.WriteString(dc, line)
		ftpSend(w, "226 Transfer complete")
		return
	}
	bw := bufio.NewWriter(dc)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		// 隐藏 . 文件与数据库/日志
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if ftpHiddenName(e.Name()) {
			continue
		}
		_, _ = bw.WriteString(formatListLine(info, e.Name(), nlst))
	}
	_ = bw.Flush()
	ftpSend(w, "226 Transfer complete")
}

func ftpHiddenName(name string) bool {
	base := filepath.Base(name)
	if strings.EqualFold(base, "httpserver_db.db") {
		return true
	}
	if strings.EqualFold(base, filepath.Base(core.Outfile)) || strings.EqualFold(base, "httpserver_log.txt") {
		return true
	}
	return false
}

func formatListLine(info os.FileInfo, name string, nlst bool) string {
	if nlst {
		if info.IsDir() {
			return name + "/\r\n"
		}
		return name + "\r\n"
	}
	mode := "-rw-r--r--"
	if info.IsDir() {
		mode = "drwxr-xr-x"
	}
	return fmt.Sprintf("%s 1 owner group %12d %s %s\r\n",
		mode, info.Size(), info.ModTime().Format("Jan _2 15:04"), name)
}

func (s *ftpSession) doRetr(w *bufio.Writer, arg string) {
	if ftpHiddenName(arg) {
		ftpSend(w, "550 Permission denied")
		return
	}
	path, err := s.resolve(arg)
	if err != nil {
		ftpSend(w, "550 "+err.Error())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		ftpSend(w, "550 "+err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		ftpSend(w, "550 Not a regular file")
		return
	}
	ftpSend(w, "150 Opening data connection")
	dc, err := s.openData()
	if err != nil {
		ftpSend(w, "425 Can't open data connection")
		return
	}
	defer dc.Close()
	_, err = io.Copy(dc, f)
	if err != nil {
		ftpSend(w, "426 Transfer aborted")
		return
	}
	ftpSend(w, "226 Transfer complete")
	core.RightLog("FTP RETR %s", path)
}

func (s *ftpSession) doStor(w *bufio.Writer, arg string) {
	path, err := s.resolve(arg)
	if err != nil {
		ftpSend(w, "550 "+err.Error())
		return
	}
	// 只允许在已存在目录下创建文件
	dir := filepath.Dir(path)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		ftpSend(w, "550 Directory not found")
		return
	}
	ftpSend(w, "150 Opening data connection")
	dc, err := s.openData()
	if err != nil {
		ftpSend(w, "425 Can't open data connection")
		return
	}
	defer dc.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		ftpSend(w, "550 "+err.Error())
		return
	}
	_, err = io.Copy(f, io.LimitReader(dc, 200<<20))
	_ = f.Close()
	if err != nil {
		ftpSend(w, "426 Transfer aborted")
		return
	}
	ftpSend(w, "226 Transfer complete")
	core.RightLog("FTP STOR %s", path)
}
