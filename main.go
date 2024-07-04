package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	version string // 编译时写入版本号

	ConfigFilePath string // 配置文件
	LogFilePath    string // 日志文件
	EnableDebug    bool   // 调试模式（详细日志）

	ForwardPort = 443       // 要转发至的目标端口
	cfg         configModel // 配置文件结构
)

// 配置文件结构
type configModel struct {
	ForwardRules  []string `yaml:"rules,omitempty"`
	ListenAddr    string   `yaml:"listen_addr,omitempty"`
	EnableSocks   bool     `yaml:"enable_socks5,omitempty"`
	SocksAddr     string   `yaml:"socks_addr,omitempty"`
	AllowAllHosts bool     `yaml:"allow_all_hosts,omitempty"`
}

func init() {
	var printVersion bool
	var help = `
SNIProxy ` + version + `
https://github.com/XIU2/SNIProxy

参数：
    -c config.yaml
        配置文件 (默认 config.yaml)
    -l sni.log
        日志文件 (默认 无)
    -d
        调试模式 (默认 关)
    -v
        程序版本
    -h
        帮助说明
`
	flag.StringVar(&ConfigFilePath, "c", "config.yaml", "配置文件")
	flag.StringVar(&LogFilePath, "l", "", "日志文件")
	flag.BoolVar(&EnableDebug, "d", false, "调试模式")
	flag.BoolVar(&printVersion, "v", false, "程序版本")
	flag.Usage = func() { fmt.Print(help) }
	flag.Parse()
	if printVersion {
		fmt.Printf("XIU2/SNIProxy %s\n", version)
		os.Exit(0)
	}
}

func main() {
	data, err := os.ReadFile(ConfigFilePath) // 读取配置文件
	if err != nil {
		serviceLogger(fmt.Sprintf("配置文件读取失败: %v", err), 31, false)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		serviceLogger(fmt.Sprintf("配置文件解析失败: %v", err), 31, false)
		os.Exit(1)
	}
	if len(cfg.ForwardRules) <= 0 && !cfg.AllowAllHosts { // 如果 rules 为空且 allow_all_hosts 不等于 true
		serviceLogger("配置文件中 rules 不能为空（除非 allow_all_hosts 等于 true）!", 31, false)
		os.Exit(1)
	}
	for _, rule := range cfg.ForwardRules { // 输出规则中的所有域名
		serviceLogger(fmt.Sprintf("加载规则: %v", rule), 32, false)
	}
	serviceLogger(fmt.Sprintf("调试模式: %v", EnableDebug), 32, false)
	serviceLogger(fmt.Sprintf("前置代理: %v", cfg.EnableSocks), 32, false)
	serviceLogger(fmt.Sprintf("任意域名: %v", cfg.AllowAllHosts), 32, false)

	startSniProxy() // 启动 SNI Proxy
}

// 启动 SNI Proxy
func startSniProxy() {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		serviceLogger(fmt.Sprintf("监听失败: %v", err), 31, false)
		os.Exit(1)
	}
	serviceLogger(fmt.Sprintf("开始监听: %v", listener.Addr()), 0, false)

	go func(listener net.Listener) {
		defer listener.Close()
		for {
			connection, err := listener.Accept()
			if err != nil {
				serviceLogger(fmt.Sprintf("接受连接请求时出错: %v", err), 31, false)
				continue
			}
			raddr := connection.RemoteAddr().(*net.TCPAddr)
			serviceLogger("连接来自: "+raddr.String(), 32, false)
			go serve(connection, raddr.String()) // 有新连接进来，启动一个新线程处理
		}
	}(listener)
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	s := <-ch
	cancel()
	fmt.Printf("\n接收到信号 %s, 退出.\n", s)
}

// 处理新连接
func serve(c net.Conn, raddr string) {
	defer c.Close()

	// 设置连接超时
	c.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 2048) // 分配缓冲区
	n, err := c.Read(buf)     // 读入新连接的内容
	if err != nil && fmt.Sprintf("%v", err) != "EOF" {
		serviceLogger(fmt.Sprintf("读取连接请求时出错: %v", err), 31, false)
		return
	}

	ServerName := getSNIServerName(buf[:n]) // 获取 SNI 域名

	if ServerName == "" {
		serviceLogger("未找到 SNI 域名, 忽略...", 31, true)
		return
	}

	if cfg.AllowAllHosts { // 如果 allow_all_hosts 为 true 则代表无需判断 SNI 域名
		serviceLogger(fmt.Sprintf("转发目标: %s:%d", ServerName, ForwardPort), 32, false)
		forward(c, buf[:n], fmt.Sprintf("%s:%d", ServerName, ForwardPort), raddr)
		return
	}

	for _, rule := range cfg.ForwardRules { // 循环遍历 Rules 中指定的白名单域名
		if strings.Contains(ServerName, rule) { // 如果 SNI 域名中包含 Rule 白名单域名（例如 www.aa.com 中包含 aa.com）则转发该连接
			serviceLogger(fmt.Sprintf("转发目标: %s:%d", ServerName, ForwardPort), 32, false)
			forward(c, buf[:n], fmt.Sprintf("%s:%d", ServerName, ForwardPort), raddr)
		}
	}
}

// 获取 SNI 域名
func getSNIServerName(buf []byte) string {
	n := len(buf)
	for i := 0; i < n; i++ {
		if i+4 < n && buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x00 && buf[i+4] == 0x00 {
			// SNI start point
			offset := i + 5
			length := int(buf[offset])
			if offset+length < n {
				return string(buf[offset+1 : offset+1+length])
			}
		}
	}
	return ""
}

// 转发连接
func forward(src net.Conn, firstPayload []byte, dstAddr, raddr string) {
	dst, err := net.Dial("tcp", dstAddr)
	if err != nil {
		serviceLogger(fmt.Sprintf("连接目标 %s 时出错: %v", dstAddr, err), 31, false)
		return
	}
	defer dst.Close()

	// 设置目标连接超时
	dst.SetDeadline(time.Now().Add(30 * time.Second))

	_, err = dst.Write(firstPayload)
	if err != nil {
		serviceLogger(fmt.Sprintf("向目标 %s 发送初始数据时出错: %v", dstAddr, err), 31, false)
		return
	}

	// 使用 io.Copy 并发地将数据从源连接传输到目标连接
	go func() {
		_, err := io.Copy(dst, src)
		if err != nil {
			serviceLogger(fmt.Sprintf("将数据从源 %s 复制到目标 %s 时出错: %v", raddr, dstAddr, err), 31, false)
		}
		dst.Close()
		src.Close()
	}()

	_, err = io.Copy(src, dst)
	if err != nil {
		serviceLogger(fmt.Sprintf("将数据从目标 %s 复制到源 %s 时出错: %v", dstAddr, raddr, err), 31, false)
	}
}

// 服务日志
func serviceLogger(message string, colorCode int, debugOnly bool) {
	if debugOnly && !EnableDebug {
		return
	}
	fmt.Printf("\x1b[%dm%s\x1b[0m\n", colorCode, message)
	if LogFilePath != "" {
		file, err := os.OpenFile(LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("无法写入日志文件: %v\n", err)
			return
		}
		defer file.Close()
		logger := io.MultiWriter(os.Stdout, file)
		fmt.Fprintf(logger, "%s\n", message)
	}
}
