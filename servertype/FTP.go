package servertype

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// ftp服务器
func FtpRunServer(port string) error {
	// 创建 TCP 服务器
	ftpserver, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	defer ftpserver.Close()

	for {
		// 等待客户端连接
		connection, err := ftpserver.Accept()
		if err != nil {
			return err
		}

		// 处理客户端连接
		go handleConnection(connection)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	// 发送欢迎消息
	sendMessage(writer, "220 Welcome to the FTP server")

	for {
		// 读取客户端命令
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("读取命令时出错:", err)
			return
		}
		// 处理命令
		cmd := strings.Fields(command)
		switch strings.ToUpper(cmd[0]) {
		case "USER":
			sendMessage(writer, "331 User name okay, need password")
		case "PASS":
			sendMessage(writer, "230 User logged in, proceed")
		case "XPWD":
			sendMessage(writer, "257 / is current directory")
		case "CWD":
			sendMessage(writer, "250 Directory changed successfully")
		case "LIST":
			sendMessage(writer, "150 Here comes the directory listing")
		case "NLST":
			sendMessage(writer, "150 Here comes the directory listing")
		case "QUIT":
			sendMessage(writer, "221 Goodbye")
			return
		default:
			sendMessage(writer, "500 Unknown command")
		}
	}
}

// 发送信息
func sendMessage(writer *bufio.Writer, message string) {
	writer.WriteString(message + "\r\n")
	writer.Flush()
}
