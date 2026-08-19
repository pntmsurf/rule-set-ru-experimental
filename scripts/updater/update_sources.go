// update_sources.go — тянет актуальные списки доменов/подсетей из внешних
// источников (AdGuard, antizapret, RIPE и т.д.), парсит их и добавляет
// в локальные файлы src/domains/*.txt и src/ips/*.txt, не трогая руками
// накопленную разметку по категориям.
//
// Запуск:
//
//	go run update_sources.go                  — обновить всё, что указано в sources.json
//	go run update_sources.go -dry-run          — только показать, что изменится
//	go run update_sources.go -only=spy.txt     — обновить конкретный файл
//
// Логика простая и однонаправленная:
//  1. читаем sources.json — для каждого целевого файла список источников + их тип разбора;
//  2. качаем каждый источник, парсим в набор доменов/подсетей;
//  3. сравниваем с тем, что уже есть в целевом файле (независимо от форматирования/комментариев);
//  4. новое дописываем в конец файла отдельным датированным блоком.
//
// Ручные комментарии и категории наверху файла никогда не трогаются и не удаляются.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/bits"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- конфиг ----------

type Source struct {
	URL  string `json:"url"`
	Type string `json:"type"` // adguard | plain | hosts | ripe-cidr
	// Для ripe-cidr:
	CountryCode string   `json:"country_code,omitempty"` // напр. "RU"
	IPTypes     []string `json:"ip_types,omitempty"`     // ["ipv4","ipv6"]
	Statuses    []string `json:"statuses,omitempty"`     // ["allocated","assigned"]
}

type Target struct {
	File    string   `json:"file"` // путь относительно scripts/, напр. "../src/domains/spy.txt"
	Sources []Source `json:"sources"`
}

// ---------- утилиты сети ----------

var httpClient = &http.Client{Timeout: 120 * time.Second}

func fetch(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Некоторые источники (antizapret, adtidy) режут автоматизированные запросы
	// по заголовкам. Используем правдоподобный браузерный UA без само-признаний.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/plain,text/html,application/octet-stream,*/*")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ---------- парсеры источников -> набор доменов/CIDR ----------

// adguardDomainRE вытаскивает домен из простого правила блокировки вида
// ||example.com^ или ||example.com^$third-party
// Правила с путями (||example.com/ads^), wildcard (*) или регэкспами (/.../)
// сознательно игнорируются — мы хотим только правила уровня "весь домен".
var adguardDomainRE = regexp.MustCompile(`^\|\|([a-zA-Z0-9][a-zA-Z0-9\-.]*\.[a-zA-Z]{2,})\^`)

func parseAdGuard(data []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// комментарии и метаданные
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		// исключения (@@||domain^) — это правила РАЗРЕШЕНИЯ, не блокировки
		if strings.HasPrefix(line, "@@") {
			continue
		}
		if !strings.HasPrefix(line, "||") {
			continue // косметические/скриптлет-правила нам не нужны
		}
		m := adguardDomainRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		domain := strings.ToLower(strings.TrimPrefix(m[1], "*."))
		out[domain] = true
	}
	return out
}

var domainLooksValidRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$`)

func parsePlainDomainList(data []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimSuffix(line, ".")
		if domainLooksValidRE.MatchString(line) {
			out[line] = true
		}
	}
	return out
}

// parseCIDRPlain — формат ipdeny.com (*.zone): один CIDR на строку, без
// заголовков и метаданных. Тот же парсер подходит и для IPv4-, и для
// IPv6-зон ipdeny.
var cidrLooksValidRE = regexp.MustCompile(`^[0-9a-fA-F:.]+/[0-9]{1,3}$`)

func parseCIDRPlain(data []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			continue
		}
		if cidrLooksValidRE.MatchString(line) {
			out[line] = true
		}
	}
	return out
}

// parseClashPayload — формат Clash rule-provider YAML:
//
//	payload:
//	  - DOMAIN-SUFFIX,openai.com
//	  - DOMAIN,api.openai.com
//	  - DOMAIN-KEYWORD,chatgpt
//
// Берём только DOMAIN / DOMAIN-SUFFIX (валидные домены); DOMAIN-KEYWORD и
// IP-CIDR пропускаем — они не домены и не годятся в наш формат.
var clashPayloadLineRE = regexp.MustCompile(`(?i)^-\s*(DOMAIN|DOMAIN-SUFFIX)\s*,\s*([^,\s]+)`)

func parseClashPayload(data []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		m := clashPayloadLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		domain := strings.ToLower(strings.TrimSuffix(m[2], "."))
		if domainLooksValidRE.MatchString(domain) {
			out[domain] = true
		}
	}
	return out
}

func parseHosts(data []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		domain := strings.ToLower(fields[1])
		if domain == "localhost" || domain == "localhost.localdomain" {
			continue
		}
		if domainLooksValidRE.MatchString(domain) {
			out[domain] = true
		}
	}
	return out
}

// ipRangeToCIDRs разбивает диапазон [start, start+count-1] на минимальный
// набор CIDR-блоков (для случаев когда count — не степень двойки, что
// в старых записях RIPE иногда встречается).
func ipRangeToCIDRs(start net.IP, count uint64) []string {
	start = start.To4()
	if start == nil || count == 0 {
		return nil
	}
	startInt := uint32(start[0])<<24 | uint32(start[1])<<16 | uint32(start[2])<<8 | uint32(start[3])
	var out []string
	remaining := count
	cur := uint64(startInt)
	for remaining > 0 {
		// максимальный размер блока, выровненного по адресу cur
		maxAlignBits := 32
		if cur != 0 {
			maxAlignBits = bits.TrailingZeros64(cur)
			if maxAlignBits > 32 {
				maxAlignBits = 32
			}
		}
		maxAlignSize := uint64(1) << uint(maxAlignBits)
		blockSize := maxAlignSize
		for blockSize > remaining {
			blockSize /= 2
		}
		prefix := 32 - int(math.Log2(float64(blockSize)))
		ip := net.IPv4(byte(cur>>24), byte(cur>>16), byte(cur>>8), byte(cur))
		out = append(out, fmt.Sprintf("%s/%d", ip.String(), prefix))
		cur += blockSize
		remaining -= blockSize
	}
	return out
}

func parseRIPEStats(data []byte, src Source) map[string]bool {
	out := map[string]bool{}
	wantTypes := map[string]bool{}
	for _, t := range src.IPTypes {
		wantTypes[t] = true
	}
	if len(wantTypes) == 0 {
		wantTypes["ipv4"] = true
		wantTypes["ipv6"] = true
	}
	wantStatus := map[string]bool{}
	for _, s := range src.Statuses {
		wantStatus[s] = true
	}
	if len(wantStatus) == 0 {
		wantStatus["allocated"] = true
		wantStatus["assigned"] = true
	}
	cc := strings.ToUpper(src.CountryCode)

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "2|") {
			continue // заголовок/версия файла
		}
		f := strings.Split(line, "|")
		// registry|cc|type|start|value|date|status[|opaque-id]
		if len(f) < 7 {
			continue
		}
		if cc != "" && strings.ToUpper(f[1]) != cc {
			continue
		}
		ipType := f[2]
		if !wantTypes[ipType] {
			continue
		}
		status := f[6]
		if !wantStatus[status] {
			continue
		}
		startStr, valueStr := f[3], f[4]
		switch ipType {
		case "ipv4":
			ip := net.ParseIP(startStr)
			count, err := strconv.ParseUint(valueStr, 10, 64)
			if ip == nil || err != nil {
				continue
			}
			for _, cidr := range ipRangeToCIDRs(ip, count) {
				out[cidr] = true
			}
		case "ipv6":
			// для ipv6 в этом формате value — это сразу префикс
			prefix, err := strconv.Atoi(valueStr)
			ip := net.ParseIP(startStr)
			if ip == nil || err != nil {
				continue
			}
			out[fmt.Sprintf("%s/%d", ip.String(), prefix)] = true
		}
	}
	return out
}

func parseSource(src Source) (map[string]bool, error) {
	data, err := fetch(src.URL)
	if err != nil {
		return nil, err
	}
	switch src.Type {
	case "adguard":
		return parseAdGuard(data), nil
	case "plain":
		return parsePlainDomainList(data), nil
	case "hosts":
		return parseHosts(data), nil
	case "ripe-cidr":
		return parseRIPEStats(data, src), nil
	case "cidr-plain":
		return parseCIDRPlain(data), nil
	case "clash-payload":
		return parseClashPayload(data), nil
	default:
		return nil, fmt.Errorf("неизвестный тип источника: %q", src.Type)
	}
}

// ---------- работа с целевыми файлами ----------

// normalizeForCompare убирает префиксы full:/regexp:/keyword: и мусор по краям,
// чтобы сравнивать записи из файла с тем, что пришло из источника.
func normalizeForCompare(line string) string {
	line = strings.TrimSpace(line)
	for _, comment := range []string{"#", "//"} {
		if idx := strings.Index(line, " "+comment); idx > 0 {
			line = line[:idx]
		}
	}
	line = strings.TrimSpace(line)
	for _, p := range []string{"full:", "regexp:", "keyword:"} {
		line = strings.TrimPrefix(line, p)
	}
	return strings.ToLower(strings.TrimSpace(line))
}

func existingEntries(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[normalizeForCompare(line)] = true
	}
	return out, sc.Err()
}

func updateTarget(t Target, dryRun bool) error {
	existing, err := existingEntries(t.File)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", t.File, err)
	}

	combined := map[string]bool{}
	var sourceLabels []string
	for _, src := range t.Sources {
		fmt.Printf("  ↓ %s (%s)\n", src.URL, src.Type)
		found, err := parseSource(src)
		if err != nil {
			fmt.Printf("    ⚠ пропущено: %v\n", err)
			continue
		}
		fmt.Printf("    получено записей: %d\n", len(found))
		for k := range found {
			combined[k] = true
		}
		sourceLabels = append(sourceLabels, src.URL)
	}

	var fresh []string
	for k := range combined {
		if !existing[k] {
			fresh = append(fresh, k)
		}
	}
	sort.Strings(fresh)

	fmt.Printf("  итого: получено %d, уже было %d, новых %d\n", len(combined), len(existing), len(fresh))

	if len(fresh) == 0 {
		fmt.Println("  ничего нового, файл не трогаем")
		return nil
	}
	if dryRun {
		fmt.Println("  [dry-run] запись пропущена, новые записи:")
		limit := len(fresh)
		if limit > 15 {
			limit = 15
		}
		for _, d := range fresh[:limit] {
			fmt.Println("    +", d)
		}
		if len(fresh) > limit {
			fmt.Printf("    ... и ещё %d\n", len(fresh)-limit)
		}
		return nil
	}

	f, err := os.OpenFile(t.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("открытие %s: %w", t.File, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "\n# === Автообновление · %s · %s ===\n", strings.Join(sourceLabels, ", "), time.Now().Format("2006-01-02"))
	for _, d := range fresh {
		fmt.Fprintln(w, d)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("  ✓ дописано %d новых записей в %s\n", len(fresh), t.File)
	return nil
}

func main() {
	dryRun := flag.Bool("dry-run", false, "показать изменения, но не писать в файлы")
	only := flag.String("only", "", "обновить только файл с этим именем (напр. spy.txt)")
	configPath := flag.String("config", "sources.json", "путь к файлу конфигурации источников")
	flag.Parse()

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("не могу прочитать %s: %v", *configPath, err)
	}
	var targets []Target
	if err := json.Unmarshal(raw, &targets); err != nil {
		log.Fatalf("плохой JSON в %s: %v", *configPath, err)
	}

	for _, t := range targets {
		if *only != "" && !strings.HasSuffix(t.File, *only) {
			continue
		}
		fmt.Printf("== %s ==\n", t.File)
		if err := updateTarget(t, *dryRun); err != nil {
			fmt.Printf("  ⚠ ошибка: %v\n", err)
		}
	}
}
