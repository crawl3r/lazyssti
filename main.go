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

// global vars for templates
var templateJinja2 = "Jinja2" // -> {{7*'7'}} would result in 7777777 in Jinja2
var templateMako = "Mako"     // -> ${7*7} -> ${"z".join("ab")} is a payload that can identify Mako
var templateSmarty = "Smarty" // -> ${7*7} -> a{*comment*}b is a payload that can identify Smarty
var templateTwig = "Twig"     // -> {{7*'7'}} would result in 49 in Twig

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

	if !quietMode {
		banner()
		fmt.Println("")
	}

	// main logic
	for _, u := range urls {
		finalUrls := []string{}

		u, payloads, results := replaceParameters(u)
		if u == "" {
			continue
		}

		if !quietMode {
			fmt.Println("Generated URL:", u)
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
			ssti, injectionPayloadElement := makeRequest(uu, results, quietMode)
			if ssti {
				// if we had a leak, let the user know
				payload := payloads[injectionPayloadElement]
				fmt.Printf("URL:%s -> Parameter Payload: %s\n", uu, payload)

				if saveOutput {
					line := uu + "|" + payload
					outputToSave = append(outputToSave, line)
				}
			}
		}
	}

	if saveOutput && len(outputToSave) > 0 {
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

func banner() {
	fmt.Println("---------------------------------------------------")
	fmt.Println("lazyssti -> Crawl3r")
	fmt.Println("Generates SSTI URL's and highlights possible vulns")
	fmt.Println("Run again with -q for cleaner output")
	fmt.Println("---------------------------------------------------")
}

// TODO: Should we randomise this? Do we care? probably not.
// We should extend this to generate a payload PER parameter incase we get multiple injection points across a site. Store the payloads + results for loop them in the regex
func generatePayload(template string, paramNumber int) (string, string) {
	payload := ""
	injectionResult := ""

	switch template {
	case templateJinja2:
		payload = "skid{{4*'4'}}life"
		injectionResult = "skid4444life"

	case templateMako:
		payload = "ski${'4'.join('dl')}ife"
		injectionResult = "skid4life"

	case templateSmarty:
		payload = "skid4{*comment*}life"
		injectionResult = "skid4life"

	case templateTwig:
		payload = "skid{{2*'2'}}life"
		injectionResult = "skid4life"

	case "unknown":
		payload = "skid${2*2}life"
		injectionResult = "skid4life"
	}

	return payload, injectionResult
}

// returns: url, slice of payloads, slice of results
func replaceParameters(url string) (string, []string, []string) {
	urlParamSplit := strings.Split(url, "?")
	if len(urlParamSplit) != 2 {
		return "", nil, nil // ? was not identified in the URL. Skip it.
	}

	if len(urlParamSplit[1]) == 0 {
		return "", nil, nil // Although we had a ? in the URL, no parameters were actually identified as the amount of chars after the ? appeared to be 0
	}

	parameterSplit := strings.Split(urlParamSplit[1], "&")
	if len(parameterSplit) == 0 {
		return "", nil, nil // Although we had a ? in the URL, no parameters were actually identified
	}

	generatedPayloadCount := 1            // start from 1 because we aren't CS students
	generatedPayloads := []string{}       // collect all payloads ready to return
	generatedPayloadResults := []string{} // collect all payload results ready to return

	injectedParams := []string{}
	for _, ps := range parameterSplit {
		paramAndVal := strings.Split(ps, "=")

		if len(paramAndVal) == 1 {
			// we didn't have a = in the parameter? Just add back to the URL
			injectedParams = append(injectedParams, ps)
		} else {
			// we did manage to split. Let's inject the payload and rebuild the URL parameter

			// create a generic payload for an unknown templating engine (should be a 'catch' all type of payload?)
			injectionPayload, injectionResult := generatePayload("unknown", generatedPayloadCount)
			newParamAndVal := paramAndVal[0] + "=" + injectionPayload
			injectedParams = append(injectedParams, newParamAndVal)

			generatedPayloads = append(generatedPayloads, injectionPayload)
			generatedPayloadResults = append(generatedPayloadResults, injectionResult)
			generatedPayloadCount += 1
		}
	}

	finalUrl := urlParamSplit[0] + "?"
	for _, ip := range injectedParams {
		finalUrl += ip + "&"
	}

	finalUrl = removeLastRune(finalUrl)
	return finalUrl, generatedPayloads, generatedPayloadResults
}

func makeRequest(url string, injectionCriteria []string, quietMode bool) (bool, int) {
	resp, err := http.Get(url)
	if err != nil {
		if !quietMode {
			fmt.Println("[error] performing the request to:", url)
		}
		return false, -1
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !quietMode {
				fmt.Println("[error] reading response bytes from:", url)
			}
			return false, -1
		}
		bodyString := string(bodyBytes)

		includesResult := false
		injectionPayload := -1
		for i, ic := range injectionCriteria {
			if doesBodyIncludeInjectionResult(ic, bodyString, quietMode) {
				includesResult = true
				injectionPayload = i
				break
			}
		}
		return includesResult, injectionPayload
	} else {
		return false, -1
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
