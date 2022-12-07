package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"regexp"
	"sync"

	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gammazero/workerpool"
	tld "github.com/jpillora/go-tld"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/projectdiscovery/retryabledns"
)

type targetDomain struct {
	mx  []string
	spf []string
}

var (
	worker     *int
	help       *bool
	exprDay    *uint
	checkWhois *bool
	verbose    *bool
	onlyMx     *bool
	output     *string
	mutex      sync.Mutex
	urls       []string
	recordInfo = make(map[string]targetDomain)
)

func init() {
	checkWhois = flag.Bool("check-whois", false, "Check whois for detecting unregistered mx domain or will be expire soon")
	exprDay = flag.Uint("expire-day", 30, "Estimated days for expiration")
	onlyMx = flag.Bool("show-only-mx", false, "show only that have mx records")
	verbose = flag.Bool("v", false, "Print all log")
	worker = flag.Int("w", 8, "number of worker")
	output = flag.String("output", "", "Save output to file as json")
	help = flag.Bool("h", false, "help")
}

func main() {
	printBanner()
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *verbose {
		printConf()
	}

	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe == 0 {
		color.Red("No data found in pipe. urls must given using pipe!")
		os.Exit(1)
	} else {
		readFromStdin()
	}

	color.Cyan("[*] Scan Starting Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	if !*checkWhois {
		color.Yellow("[!] Check-whois argument was not provided. It will not checked whois lookup against MX domains that found.")
	}

	lenUrl := len(urls)
	color.Cyan("[*] %d domain will be scanned.", lenUrl)

	wp := workerpool.New(*worker)

	for id, r := range urls {
		r := r
		wp.Submit(func() {
			getDNSRecord(id, r)
		})
	}

	wp.StopWait()
	defer color.Cyan("[*] End Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	if *output != "" {
		defer writeToFile(*output, recordInfo)
	}

	if *onlyMx {
		defer scanSummary()
	}

	defer whoisMXDomain(recordInfo)
	if !*onlyMx {
		defer whoisSPFDomain(recordInfo)
	}
	if *checkWhois {
		defer color.Cyan("[*] Domains that expire in less than %d days", *exprDay)
	}
}

func readFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		u := scanner.Text()
		if strings.HasPrefix(u, "https://") {
			url := strings.ReplaceAll(u, "https://", "")
			urls = append(urls, url)

		} else if strings.HasPrefix(u, "http://") {
			url := strings.ReplaceAll(u, "http://", "")
			urls = append(urls, url)
		} else {
			urls = append(urls, u)
		}
	}
}

func getDNSRecord(id int, domain string) {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.0.0.1:53", "208.67.222.222:53"}
	retries := 3
	hostname := domain
	dnsClient := retryabledns.New(resolvers, retries)
	_, err := dnsClient.Resolve(hostname)
	if err != nil {
		color.Yellow("%s -> %s skipping...", err, hostname)
	} else {
		// I want to make only one query :( - RTFM
		dnsResponsesMX, err := dnsClient.Query(hostname, dns.TypeMX)
		dnsResponsesSPF, err2 := dnsClient.Query(hostname, dns.TypeTXT)

		if err != nil && err2 != nil {
			color.Yellow("%s -> %s skipping...", err, hostname)
		} else {
			if *verbose {
				log.Println(domain, "MX", dnsResponsesMX.MX)
			}

			if len(dnsResponsesMX.MX) > 0 {
				if *onlyMx {
					log.Println(domain, "MX", dnsResponsesMX.MX)
				}
				if *checkWhois {
					parseMXDomain(domain, dnsResponsesMX.MX)
				}
			}
			if !*onlyMx {
				if len(dnsResponsesSPF.TXT) > 0 {
					parseSPFDomain(domain, dnsResponsesSPF.TXT)
				}
			}
		}
	}
}

// find mx domain. (sub.mail.google.com -> google.com)
func parseMXDomain(domain string, mxlist []string) {
	for _, mxd := range mxlist {
		// for parsing correctly added http:// schema.
		u, _ := tld.Parse("http://" + mxd)
		if u != nil {
			mxDomain := u.Domain + "." + u.TLD
			mutex.Lock()
			if !contains(recordInfo[mxDomain].mx, domain) {
				entry := recordInfo[mxDomain]
				entry.mx = append(entry.mx, domain)
				recordInfo[mxDomain] = entry
			}
			mutex.Unlock()
		} else {
			if *verbose {
				log.Println("Error Detected!", mxd)
			}
		}

	}
}

func parseSPFDomain(domain string, spflist []string) {
	pat := regexp.MustCompile(`[a-zA-Z0-9._-]*\.[a-z]+`)
	for _, spfd := range spflist {
		// for parsing correctly added http:// schema.
		if strings.Contains(spfd, "v=spf") {
			matches := pat.FindAllStringSubmatch(spfd, -1) // matches is [][]string
			if *verbose {
				log.Println(domain, "SPF", matches)
			}
			for _, match := range matches {
				u, _ := tld.Parse("http://" + match[0])
				if u != nil {
					spfDomain := u.Domain + "." + u.TLD
					mutex.Lock()
					if !contains(recordInfo[spfDomain].spf, domain) {
						entry := recordInfo[spfDomain]
						entry.spf = append(entry.spf, domain)
						recordInfo[spfDomain] = entry
					}
					mutex.Unlock()
				} else {
					if *verbose {
						log.Println("Error Detected!", match[0])
					}
				}
			}
		}

	}
}

func whoisMXDomain(domains map[string]targetDomain) {
	for mxDomain, dmn := range domains {
		respWhois, err := whois.Whois(mxDomain)
		if err == nil {
			if result, err := whoisparser.Parse(respWhois); err == nil {
				if result.Domain.ExpirationDate != "" {
					expireDomain(mxDomain, result.Domain.ExpirationDate, dmn.mx, "MX")
				}
			} else if err.Error() == "whoisparser: domain is not found" {
				color.Green("[+] Unregistered MX domain was detected! %s MX %s", dmn.mx, mxDomain)
			} else {
				if *verbose {
					fmt.Println("Error Detected!", err)
				}
			}
		}
	}
}

func whoisSPFDomain(domains map[string]targetDomain) {
	for spfDomain, dmn := range domains {
		respWhois, err := whois.Whois(spfDomain)
		if err == nil {
			if result, err := whoisparser.Parse(respWhois); err == nil {
				if result.Domain.ExpirationDate != "" {
					expireDomain(spfDomain, result.Domain.ExpirationDate, dmn.spf, "SPF")
				}
			} else if err.Error() == "whoisparser: domain is not found" {
				color.Green("[+] Unregistered SPF domain was detected! %s SPF %s", dmn.spf, spfDomain)
			} else {
				if *verbose {
					fmt.Println("Error Detected!", err)
				}
			}
		}
	}
}

func contains(domains []string, domain string) bool {
	for _, d := range domains {
		if d == domain {
			return true
		}
	}
	return false
}

func expireDomain(domain, expireDate string, dmn []string, recordType string) {
	date := time.Now()
	format := "2006-01-02T15:04:05Z"
	then, _ := time.Parse(format, expireDate)
	diff := then.Sub(date)
	daysRemain := uint(diff.Hours() / 24)
	lenDmn := len(dmn)
	if daysRemain < *exprDay {
		color.Green("[+] %s will be expired after [%d] days. It is being used by %d different domain. Expire Time: [%s]. Domains that are used by this %s:", domain, daysRemain, lenDmn, expireDate, recordType) // number of days
		fmt.Println(dmn)
	}
}

func scanSummary() {
	for mx, domains := range recordInfo {
		fmt.Printf("[MX] %s being used %d different domains. %s mx record being used by these domains : %s \n", mx, len(domains.mx), mx, domains.mx)
		fmt.Printf("[SPF] %s being used %d different domains. %s mx record being used by these domains : %s \n", mx, len(domains.spf), mx, domains.spf)
	}
}

func writeToFile(filename string, data map[string]targetDomain) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	mapToJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error: ", err.Error())
	} else {
		_, err = io.WriteString(file, string(mapToJson))
		if err != nil {
			return err
		}
	}
	color.Cyan("[*] Scan results was saved to %s", filename)
	return file.Sync()
}

func printConf() {
	fmt.Printf(`
_____________________________________________

Worker      	: %d
Max Expire Day	: %d
Check Whois  	: %t
Show Only MX  	: %t
Verbose      	: %t
Output File  	: %s
_____________________________________________

`, *worker, *exprDay, *checkWhois, *onlyMx, *verbose, *output)
}

func printBanner() {
	fmt.Println(`

 /$$      /$$ /$$   /$$       /$$ /$$$$$$  /$$$$$$$  /$$$$$$$$        /$$               /$$                                                        
| $$$    /$$$| $$  / $$      /$$//$$__  $$| $$__  $$| $$_____/       | $$              | $$                                                        
| $$$$  /$$$$|  $$/ $$/     /$$/| $$  \__/| $$  \ $$| $$            /$$$$$$    /$$$$$$ | $$   /$$  /$$$$$$   /$$$$$$  /$$    /$$ /$$$$$$   /$$$$$$ 
| $$ $$/$$ $$ \  $$$$/     /$$/ |  $$$$$$ | $$$$$$$/| $$$$$ /$$$$$$|_  $$_/   |____  $$| $$  /$$/ /$$__  $$ /$$__  $$|  $$  /$$//$$__  $$ /$$__  $$
| $$  $$$| $$  >$$  $$    /$$/   \____  $$| $$____/ | $$__/|______/  | $$      /$$$$$$$| $$$$$$/ | $$$$$$$$| $$  \ $$ \  $$/$$/| $$$$$$$$| $$  \__/
| $$\  $ | $$ /$$/\  $$  /$$/    /$$  \ $$| $$      | $$             | $$ /$$ /$$__  $$| $$_  $$ | $$_____/| $$  | $$  \  $$$/ | $$_____/| $$      
| $$ \/  | $$| $$  \ $$ /$$/    |  $$$$$$/| $$      | $$             |  $$$$/|  $$$$$$$| $$ \  $$|  $$$$$$$|  $$$$$$/   \  $/  |  $$$$$$$| $$      
|__/     |__/|__/  |__/|__/      \______/ |__/      |__/              \___/   \_______/|__/  \__/ \_______/ \______/     \_/    \_______/|__/


hunting misconfigured MX & SPF records
@zi0Black | original work by @musana
 `)
}
