package core

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 轻量持久化（用户 + 聊天记录），纯 Go SQLite，无需 CGO
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

var globalStore *Store

// OpenStore 打开/创建数据库
func OpenStore(path string) (*Store, error) {
	// 获取当前程序所在文件夹路径
	currentPath := getCurrentPath()
	if path == "" {
		path = filepath.Join(currentPath, "httpserver_db.db")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(currentPath, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	globalStore = s
	InfoLog("数据库路径：%s", path)
	return s, nil
}

// GetStore 返回全局 store（可能为 nil）
func GetStore() *Store { return globalStore }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  msgtype INTEGER NOT NULL,
  data TEXT NOT NULL,
  targets TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
`)
	return err
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ListUsers 读取全部用户名
func (s *Store) ListUsers() ([]string, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT name FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AddUser 添加用户（已存在则忽略）
func (s *Store) AddUser(name string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO users(name, created_at) VALUES(?, ?)`,
		name, time.Now().Format(time.RFC3339),
	)
	return err
}

// DeleteUser 删除用户
func (s *Store) DeleteUser(name string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM users WHERE name = ?`, name)
	return err
}

// ClearUsers 清空用户
func (s *Store) ClearUsers() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM users`)
	return err
}

// EnsureUsers 批量确保用户存在
func (s *Store) EnsureUsers(names []string) error {
	for _, n := range names {
		if n == "" {
			continue
		}
		if err := s.AddUser(n); err != nil {
			return err
		}
	}
	return nil
}

// ChatMsg 历史消息
type ChatMsg struct {
	ID       int64
	UserName string
	MsgType  int
	Data     string
	Targets  string
	Time     string
}

// SaveMessage 保存聊天消息
func (s *Store) SaveMessage(username string, msgtype int, data, targets string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO messages(username, msgtype, data, targets, created_at) VALUES(?,?,?,?,?)`,
		username, msgtype, data, targets, time.Now().Format("2006-01-02 15:04:05"),
	)
	return err
}

// messageVisibleTo 判断历史消息对 viewer 是否可见。
// targets 为空：群发，所有人可见；非空：仅 targets 列表内用户（含发送者）可见。
func messageVisibleTo(targets, viewer string) bool {
	targets = strings.TrimSpace(targets)
	if targets == "" {
		return true
	}
	viewer = strings.TrimSpace(viewer)
	for _, part := range strings.Split(targets, ",") {
		if strings.TrimSpace(part) == viewer {
			return true
		}
	}
	return false
}

// RecentMessages 最近 N 条（不过滤，内部/管理用）
func (s *Store) RecentMessages(limit int) ([]ChatMsg, error) {
	return s.RecentMessagesForUser("", limit)
}

// RecentMessagesForUser 最近对 viewer 可见的消息。
// viewer 为空时返回全部；非空时过滤私聊（@）消息。
func (s *Store) RecentMessagesForUser(viewer string, limit int) ([]ChatMsg, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	// 多取一些再按可见性过滤，避免私聊把名额占满导致群发历史过少
	fetch := limit
	if viewer != "" {
		fetch = limit * 5
		if fetch < 100 {
			fetch = 100
		}
		if fetch > 500 {
			fetch = 500
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
SELECT id, username, msgtype, data, COALESCE(targets,''), created_at FROM (
  SELECT id, username, msgtype, data, targets, created_at FROM messages
  ORDER BY id DESC LIMIT ?
) ORDER BY id ASC`, fetch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []ChatMsg
	for rows.Next() {
		var m ChatMsg
		if err := rows.Scan(&m.ID, &m.UserName, &m.MsgType, &m.Data, &m.Targets, &m.Time); err != nil {
			return nil, err
		}
		all = append(all, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if viewer == "" {
		if len(all) > limit {
			all = all[len(all)-limit:]
		}
		return all, nil
	}
	var out []ChatMsg
	for _, m := range all {
		if messageVisibleTo(m.Targets, viewer) {
			out = append(out, m)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// MergeUserLists 合并 CLI 用户与库中用户，去重保序
func MergeUserLists(cli []string, dbUsers []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]string{}, cli...), dbUsers...) {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// MustOpenStore 打开数据库，失败只打日志返回 nil
func MustOpenStore(path string) *Store {
	s, err := OpenStore(path)
	if err != nil {
		ErrorLog("打开数据库失败：%v（将不持久化）", err)
		return nil
	}
	return s
}

// DBPathHelp 供日志
func DBPathHelp(path string) string {
	if path == "" {
		return filepath.Join(RootDir, "httpserver_db.db")
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(RootDir, path)
}

// FormatErr 小工具
func FormatErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(err)
}
