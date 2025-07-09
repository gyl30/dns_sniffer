//go:build linux

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	fname = flag.String("r", "eth0", "Interface or PCAP file")
	db    *sql.DB
)

type DNSPacket struct {
	Timestamp     time.Time
	SrcIP         string
	DstIP         string
	SrcPort       int
	DstPort       int
	TransactionID uint16
	IsResponse    bool
	Questions     []DNSQuestion
	Answers       []DNSAnswer
}

type DNSQuestion struct {
	Name  string
	Type  string
	Class string
}

type DNSAnswer struct {
	Name string
	Type string
	Data string
	TTL  uint32
}

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}
	timestamp := entry.Time.Format("20060102 15:04:05.000000")
	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		fmt.Fprintf(b, "%-24s %s %s %s:%d\n", timestamp, entry.Level, entry.Message, fName, entry.Caller.Line)
	} else {
		fmt.Fprintf(b, "%-24s %s %s\n", timestamp, entry.Level, entry.Message)
	}
	return b.Bytes(), nil
}

func ConfigLogger() {
	logger := &lumberjack.Logger{
		Filename:   "dns.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     28,
	}
	logrus.SetOutput(io.MultiWriter(os.Stdout, logger))
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&MyFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func InitDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./dns_packets.db")
	if err != nil {
		return err
	}
	schema := `
	CREATE TABLE IF NOT EXISTS dns_packets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT,
		src_ip TEXT,
		dst_ip TEXT,
		src_port INTEGER,
		dst_port INTEGER,
		transaction_id INTEGER,
		is_response INTEGER
	);
	CREATE TABLE IF NOT EXISTS dns_names (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE
	);
	CREATE TABLE IF NOT EXISTS dns_questions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		packet_id INTEGER,
		name_id INTEGER,
		type TEXT,
		class TEXT,
		FOREIGN KEY(packet_id) REFERENCES dns_packets(id),
		FOREIGN KEY(name_id) REFERENCES dns_names(id)
	);
	CREATE TABLE IF NOT EXISTS dns_answers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		packet_id INTEGER,
		name_id INTEGER,
		type TEXT,
		data TEXT,
		ttl INTEGER,
		FOREIGN KEY(packet_id) REFERENCES dns_packets(id),
		FOREIGN KEY(name_id) REFERENCES dns_names(id)
	);
	CREATE INDEX IF NOT EXISTS idx_packet_time ON dns_packets(timestamp);
	CREATE INDEX IF NOT EXISTS idx_packet_srcip ON dns_packets(src_ip);
	CREATE INDEX IF NOT EXISTS idx_name_text ON dns_names(name);
	`
	_, err = db.Exec(schema)
	return err
}

func saveDNSPacket(pkt DNSPacket) error {
	start := time.Now()
	tx, err := db.Begin()
	if err != nil {
		logrus.Errorf("saveDNSPacket: begin transaction failed: %v", err)
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			logrus.Infof("saveDNSPacket: transaction rollback due to error")
		}
	}()

	logrus.Infof("saveDNSPacket: start saving DNS packet TxID=%d SrcIP=%s DstIP=%s Questions=%d Answers=%d",
		pkt.TransactionID, pkt.SrcIP, pkt.DstIP, len(pkt.Questions), len(pkt.Answers))

	// 插入dns_packets表
	res, err := tx.Exec(
		`INSERT INTO dns_packets (timestamp, src_ip, dst_ip, src_port, dst_port, transaction_id, is_response)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		pkt.Timestamp.UTC().Format(time.RFC3339), pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.TransactionID, pkt.IsResponse)
	if err != nil {
		logrus.Errorf("saveDNSPacket: insert dns_packets failed: %v", err)
		return err
	}
	packetID, err := res.LastInsertId()
	if err != nil {
		logrus.Warnf("saveDNSPacket: get last insert id failed: %v", err)
	}

	nameCache := make(map[string]int64)

	getOrInsertName := func(name string) (int64, error) {
		if id, ok := nameCache[name]; ok {
			return id, nil
		}
		var id int64
		err := tx.QueryRow(`SELECT id FROM dns_names WHERE name = ?`, name).Scan(&id)
		if err == nil {
			logrus.Debugf("saveDNSPacket: domain name exists: %s id=%d", name, id)
			nameCache[name] = id
			return id, nil
		}
		if err != sql.ErrNoRows {
			logrus.Errorf("saveDNSPacket: query dns_names failed: %v", err)
			return 0, err
		}
		res, err := tx.Exec(`INSERT INTO dns_names (name) VALUES (?)`, name)
		if err != nil {
			logrus.Errorf("saveDNSPacket: insert dns_names failed: %v", err)
			return 0, err
		}
		id, err = res.LastInsertId()
		if err != nil {
			logrus.Warnf("saveDNSPacket: get last insert id for dns_names failed: %v", err)
		}
		logrus.Infof("saveDNSPacket: inserted new domain name: %s id=%d", name, id)
		nameCache[name] = id
		return id, nil
	}

	for i, q := range pkt.Questions {
		nameID, err := getOrInsertName(q.Name)
		if err != nil {
			logrus.Errorf("saveDNSPacket: getOrInsertName failed for question %d: %v", i, err)
			return err
		}
		_, err = tx.Exec(
			`INSERT INTO dns_questions (packet_id, name_id, type, class) VALUES (?, ?, ?, ?)`,
			packetID, nameID, q.Type, q.Class)
		if err != nil {
			logrus.Errorf("saveDNSPacket: insert question %d failed: %v", i, err)
			return err
		}
		logrus.Debugf("saveDNSPacket: inserted question %d name=%s type=%s class=%s", i, q.Name, q.Type, q.Class)
	}

	for i, a := range pkt.Answers {
		nameID, err := getOrInsertName(a.Name)
		if err != nil {
			logrus.Errorf("saveDNSPacket: getOrInsertName failed for answer %d: %v", i, err)
			return err
		}
		_, err = tx.Exec(
			`INSERT INTO dns_answers (packet_id, name_id, type, data, ttl) VALUES (?, ?, ?, ?, ?)`,
			packetID, nameID, a.Type, a.Data, a.TTL)
		if err != nil {
			logrus.Errorf("saveDNSPacket: insert answer %d failed: %v", i, err)
			return err
		}
		logrus.Debugf("saveDNSPacket: inserted answer %d name=%s type=%s data=%s ttl=%d", i, a.Name, a.Type, a.Data, a.TTL)
	}

	if err := tx.Commit(); err != nil {
		logrus.Errorf("saveDNSPacket: commit transaction failed: %v", err)
		return err
	}

	logrus.Infof("saveDNSPacket: finished saving DNS packet TxID=%d, total cost=%v", pkt.TransactionID, time.Since(start))
	return nil
}

func main() {
	flag.Parse()
	ConfigLogger()
	if err := InitDB(); err != nil {
		logrus.Fatalf("DB init failed: %v", err)
	}
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	pcapFile := *fname
	if len(pcapFile) != 0 {
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			handle, err := pcap.OpenLive(pcapFile, 65536, true, pcap.BlockForever)
			if err != nil {
				logrus.Errorf("PCAP OpenLive error %s", err.Error())
				return
			}
			go handlePcap(handle, stopper)
		} else {
			handle, err := pcap.OpenOffline(pcapFile)
			if err != nil {
				logrus.Errorf("PCAP OpenOffline error %s", err.Error())
				return
			}
			go handlePcap(handle, stopper)
		}
	}

	go func() {
		http.HandleFunc("/", handleIndex)
		http.HandleFunc("/ip", handleIPQueries)
		http.HandleFunc("/top", handleTopDomains)
		http.HandleFunc("/recent-packets", handleRecentPackets)
		http.HandleFunc("/api/queries-by-hour", handleQueriesByHour)
		http.HandleFunc("/api/queries-per-hour", handleQueriesPerHour)
		logrus.Info("Starting web server on :8183")
		if err := http.ListenAndServe(":8183", nil); err != nil {
			logrus.Fatalf("Web server failed: %v", err)
		}
	}()

	<-stopper
	logrus.Info("Stopping...")
	time.Sleep(100 * time.Millisecond)
}

func handlePcap(handle *pcap.Handle, stopper <-chan os.Signal) {
	handle.SetBPFFilter("udp and port 53")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				return
			}
			handlePacket(packet)
		case <-stopper:
			return
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	logrus.Debug("handlePacket: new packet received")

	var pkt DNSPacket
	pkt.Timestamp = time.Now()

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		logrus.Debugf("handlePacket: IPv4 src=%s dst=%s", pkt.SrcIP, pkt.DstIP)
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		logrus.Debugf("handlePacket: IPv6 src=%s dst=%s", pkt.SrcIP, pkt.DstIP)
	} else {
		logrus.Warn("handlePacket: no IP layer found")
	}

	if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		pkt.SrcPort = int(u.SrcPort)
		pkt.DstPort = int(u.DstPort)
		logrus.Debugf("handlePacket: UDP srcPort=%d dstPort=%d", pkt.SrcPort, pkt.DstPort)
	} else {
		logrus.Warn("handlePacket: no UDP layer found")
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		pkt.TransactionID = dns.ID
		pkt.IsResponse = dns.QR

		logrus.Infof("handlePacket: DNS TxID=%d QR=%t Questions=%d Answers=%d",
			pkt.TransactionID, pkt.IsResponse, len(dns.Questions), len(dns.Answers))

		for i, q := range dns.Questions {
			qs := DNSQuestion{
				Name:  string(q.Name),
				Type:  q.Type.String(),
				Class: q.Class.String(),
			}
			pkt.Questions = append(pkt.Questions, qs)
			logrus.Debugf("handlePacket: Question[%d]: Name=%s Type=%s Class=%s",
				i, qs.Name, qs.Type, qs.Class)
		}

		for i, a := range dns.Answers {
			var data string
			switch a.Type {
			case layers.DNSTypeA, layers.DNSTypeAAAA:
				data = a.IP.String()
			case layers.DNSTypeCNAME:
				data = string(a.CNAME)
			case layers.DNSTypeNS:
				data = string(a.NS)
			case layers.DNSTypePTR:
				data = string(a.PTR)
			case layers.DNSTypeTXT:
				if len(a.TXTs) > 0 {
					data = string(a.TXTs[0])
				}
			default:
				data = "<unsupported>"
			}

			ans := DNSAnswer{
				Name: string(a.Name),
				Type: a.Type.String(),
				Data: data,
				TTL:  a.TTL,
			}
			pkt.Answers = append(pkt.Answers, ans)
			logrus.Debugf("handlePacket: Answer[%d]: Name=%s Type=%s Data=%s TTL=%d",
				i, ans.Name, ans.Type, ans.Data, ans.TTL)
		}

		if err := saveDNSPacket(pkt); err != nil {
			logrus.Errorf("handlePacket: saveDNSPacket error: %v", err)
		}
	} else {
		logrus.Warn("handlePacket: no DNS layer found")
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

func handleTopDomains(w http.ResponseWriter, r *http.Request) {
	// 查询请求次数最多的域名，限制100条
	query := `
	SELECT n.name, COUNT(*) as count
	FROM dns_questions q
	JOIN dns_names n ON q.name_id = n.id
	GROUP BY n.name
	ORDER BY count DESC
	LIMIT 100;
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"name": name, "count": count})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleRecentPackets(w http.ResponseWriter, r *http.Request) {
	limit := 100
	query := `
	SELECT datetime(timestamp, 'localtime') AS timestamp, src_ip, dst_ip
	FROM dns_packets
	ORDER BY timestamp DESC
	LIMIT ?
	`
	rows, err := db.Query(query, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var timestamp string
		var srcIP, dstIP string
		if err := rows.Scan(&timestamp, &srcIP, &dstIP); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"timestamp": timestamp,
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIPQueries(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip parameter", 400)
		return
	}
	query := `
	SELECT datetime(p.timestamp, 'localtime') AS timestamp, n.name, q.type, q.class
	FROM dns_packets p
	JOIN dns_questions q ON p.id = q.packet_id
	JOIN dns_names n ON q.name_id = n.id
	WHERE p.src_ip = ? OR p.dst_ip = ?
	ORDER BY p.timestamp DESC
	LIMIT 20
	`
	rows, err := db.Query(query, ip, ip)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var timestamp, name, qtype, qclass string
		if err := rows.Scan(&timestamp, &name, &qtype, &qclass); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"timestamp": timestamp,
			"name":      name,
			"type":      qtype,
			"class":     qclass,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleQueriesPerHour(w http.ResponseWriter, r *http.Request) {
	query := `
	SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, 'localtime')) AS hour,
	       COUNT(*) as count
	FROM dns_packets p
	JOIN dns_questions q ON p.id = q.packet_id
	GROUP BY hour
	ORDER BY hour ASC
	LIMIT 48;
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var hour string
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"hour":  hour,
			"count": count,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleQueriesByHour(w http.ResponseWriter, r *http.Request) {
	hour := r.URL.Query().Get("hour")
	if hour == "" {
		http.Error(w, "missing hour parameter", 400)
		return
	}
	logrus.Infof("[/api/queries-by-hour] Received request for hour: %s", hour)

	// hour 形如 "2025-07-09 03:00"
	// 查询该小时范围：>= hour and < hour+1 hour
	query := `
    SELECT datetime(timestamp, 'localtime') AS timestamp, n.name, q.type, q.class, p.src_ip, p.dst_ip
    FROM dns_packets p
    JOIN dns_questions q ON p.id = q.packet_id
    JOIN dns_names n ON q.name_id = n.id
    WHERE is_response = 0
      AND datetime(timestamp, 'localtime') >= ?
      AND datetime(timestamp, 'localtime') < datetime(?, '+1 hour')
    ORDER BY timestamp ASC
    LIMIT 100;
    `
	rows, err := db.Query(query, hour, hour)
	if err != nil {
		logrus.Errorf("[/api/queries-by-hour] DB query error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var timestamp, name, qtype, qclass, srcIP, dstIP string
		if err := rows.Scan(&timestamp, &name, &qtype, &qclass, &srcIP, &dstIP); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"timestamp": timestamp,
			"name":      name,
			"type":      qtype,
			"class":     qclass,
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
