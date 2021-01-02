package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	urls := []string{}

	for sc.Scan() {
		domain := strings.ToLower(sc.Text())

		if domain != "" && len(domain) > 0 {
			urls = append(urls, domain)
		}
	}

	var outputFileFlag string
	flag.StringVar(&outputFileFlag, "o", "", "Output file for identified leakd source")
	quietModeFlag := flag.Bool("q", false, "Only output the URL's with leaked source")
	flag.Parse()

	quietMode := *quietModeFlag
	saveOutput := outputFileFlag != ""
	outputToSave := []string{}

	injectionPayload, injectionResult := generatePayload()

	// main logic
	for _, u := range urls {
		finalUrls := []string{}

		u = replaceParameters(u, injectionPayload)
		if u == "" {
			continue
		}

		// If the identified URL has neither http or https infront of it. Create both and scan them.
		if !strings.Contains(u, "http://") && !strings.Contains(u, "https://") {
			finalUrls = append(finalUrls, "http://"+u)
			finalUrls = append(finalUrls, "https://"+u)
		} else {
			// else, just scan the submitted one as it has either protocol
			finalUrls = append(finalUrls, u)
		}

		// now loop the slice of finalUrls (either submitted OR 2 urls with http/https appended to them)
		for _, uu := range finalUrls {
			ssti := makeRequest(uu, injectionResult, quietMode)
			if ssti {
				// if we had a leak, let the user know
				fmt.Printf("%s\n", uu)

				if saveOutput {
					outputToSave = append(outputToSave, uu)
				}
			}
		}
	}

	if saveOutput {
		file, err := os.OpenFile(outputFileFlag, os.O_CREATE|os.O_WRONLY, 0644)

		if err != nil && !quietMode {
			log.Fatalf("failed creating file: %s", err)
		}

		datawriter := bufio.NewWriter(file)

		for _, data := range outputToSave {
			_, _ = datawriter.WriteString(data + "\n")
		}

		datawriter.Flush()
		file.Close()
	}
}

// TODO: Should we randomise this? Do we care? probably not.
// We should extend this to generate a payload PER parameter incase we get multiple injection points across a site. Store the payloads + results for loop them in the regex
func generatePayload() (string, string) {
	return "skid{{2*2}}life", "skid4life"
}

func replaceParameters(url string, payload string) string {
	urlParamSplit := strings.Split(url, "?")
	if len(urlParamSplit) != 2 {
		return "" // ? was not identified in the URL. Skip it.
	}

	if len(urlParamSplit[1]) == 0 {
		return "" // Although we had a ? in the URL, no parameters were actually identified as the amount of chars after the ? appeared to be 0
	}

	parameterSplit := strings.Split(urlParamSplit[1], "&")
	if len(parameterSplit) == 0 {
		return "" // Although we had a ? in the URL, no parameters were actually identified
	}

	injectedParams := []string{}
	for _, ps := range parameterSplit {
		paramAndVal := strings.Split(ps, "=")

		if len(paramAndVal) == 1 {
			// we didn't have a = in the parameter? Just add back to the URL
			injectedParams = append(injectedParams, ps)
		} else {
			// we did manage to split. Let's inject the payload and rebuild the URL parameter
			newParamAndVal := paramAndVal[0] + "=" + payload
			injectedParams = append(injectedParams, newParamAndVal)
		}
	}

	finalUrl := urlParamSplit[0] + "?"
	for _, ip := range injectedParams {
		finalUrl += ip + "&"
	}

	finalUrl = removeLastRune(finalUrl)
	fmt.Println(finalUrl)
	return finalUrl
}

func makeRequest(url string, injectionCriteria string, quietMode bool) bool {
	resp, err := http.Get(url)
	if err != nil {
		if !quietMode {
			fmt.Println("[error] performing the request to:", url)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !quietMode {
				fmt.Println("[error] reading response bytes from:", url)
			}
			return false
		}
		bodyString := string(bodyBytes)
		return doesBodyIncludeInjectionResult(injectionCriteria, bodyString, quietMode)
	} else {
		return false
	}
}

func doesBodyIncludeInjectionResult(criteria string, body string, quietMode bool) bool {
	r, _ := regexp.Compile(criteria)
	return r.MatchString(body)
}

// use runes so we aren't just stuck with ASCII incase we have some funky use cases for this
func removeLastRune(s string) string {
	r := []rune(s)
	return string(r[:len(r)-1])
}
