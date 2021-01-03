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
	"strconv"
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
	flag.StringVar(&outputFileFlag, "o", "", "Output file for possible SSTI vulnerable URLs")
	quietModeFlag := flag.Bool("q", false, "Only output the URLs with possible SSTI vulnerabilities")
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

		u, payloads, results := replaceParameters(u, -1, "unknown") // we pass -1 here so we replace all parameters
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
			ssti, injectionPayloadElements := makeRequest(uu, results, quietMode)
			if ssti {
				// if we had a possible SSTI win, let the user know
				workingPayloads := ""
				for i, wp := range injectionPayloadElements {
					workingPayloads += payloads[wp]

					if i != len(injectionPayloadElements)-1 {
						workingPayloads += "|"
					}
				}

				fmt.Printf("URL:%s -> Parameter Payload: %s\n", uu, workingPayloads)

				// now we have seen a possible win, try figure out the template based on the hardcoded knowledge we have
				attemptToIdentifyEngine(uu, injectionPayloadElements[0], quietMode) // this injectionPayloadElements[0] allows us to just replace the first vulnerable URL param

				if saveOutput {
					line := uu + "|" + workingPayloads
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
		payload = "skid{{" + strconv.Itoa(paramNumber) + "*'" + strconv.Itoa(paramNumber) + "'}}life"
		injectionResult = "skid" + strings.Repeat(strconv.Itoa(paramNumber), paramNumber) + "life"

	case templateMako:
		payload = "ski${'" + strconv.Itoa(paramNumber) + "'.join('dl')}ife"
		injectionResult = "skid" + strconv.Itoa(paramNumber) + "life"

	case templateSmarty:
		payload = "skid" + strconv.Itoa(paramNumber) + "{*comment*}life"
		injectionResult = "skid" + strconv.Itoa(paramNumber) + "life"

	case templateTwig:
		payload = "skid{{" + strconv.Itoa(paramNumber) + "*'" + strconv.Itoa(paramNumber) + "'}}life"
		injectionResult = "skid" + strconv.Itoa(paramNumber*paramNumber) + "life"

	case "unknown":
		payload = "skid${" + strconv.Itoa(paramNumber) + "*" + strconv.Itoa(paramNumber) + "}life"
		injectionResult = "skid" + strconv.Itoa(paramNumber*paramNumber) + "life"
	}

	return payload, injectionResult
}

// returns: url, slice of payloads, slice of results
func replaceParameters(url string, paramToReplace int, template string) (string, []string, []string) {
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
	for i, ps := range parameterSplit {
		// only replace the target parameter if specified in the function parameters
		if paramToReplace != -1 {
			if i != paramToReplace {
				injectedParams = append(injectedParams, ps)
				continue
			}
		}

		paramAndVal := strings.Split(ps, "=")

		if len(paramAndVal) == 1 {
			// we didn't have a = in the parameter? Just add back to the URL
			injectedParams = append(injectedParams, ps)
		} else {
			// we did manage to split. Let's inject the payload and rebuild the URL parameter

			// create a generic payload for an unknown templating engine (should be a 'catch' all type of payload?)
			injectionPayload, injectionResult := generatePayload(template, generatedPayloadCount)
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

func makeRequest(url string, injectionCriteria []string, quietMode bool) (bool, []int) {
	resp, err := http.Get(url)
	if err != nil {
		if !quietMode {
			fmt.Println("[error] performing the request to:", url)
		}
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !quietMode {
				fmt.Println("[error] reading response bytes from:", url)
			}
			return false, nil
		}
		bodyString := string(bodyBytes)

		includesResult := false
		workingPayloads := []int{}
		for i, ic := range injectionCriteria {
			if doesBodyIncludeInjectionResult(ic, bodyString, quietMode) {
				includesResult = true
				workingPayloads = append(workingPayloads, i) // we probably want to accumulate all working payloads as multiple might trigger in one page?
				break
			}
		}
		return includesResult, workingPayloads
	} else {
		return false, nil
	}
}

func doesBodyIncludeInjectionResult(criteria string, body string, quietMode bool) bool {
	r, _ := regexp.Compile(criteria)
	return r.MatchString(body)
}

func attemptToIdentifyEngine(url string, vulnParamElement int, quietMode bool) []string {
	// this might be meh, but make a request to the same URL per template based on the payloads we have
	// for this, we don't care about the number of parameters - we just want to try identify the template engine

	/*
		var templateJinja2 = "Jinja2" // -> {{7*'7'}} would result in 7777777 in Jinja2
		var templateMako = "Mako"     // -> ${7*7} -> ${"z".join("ab")} is a payload that can identify Mako
		var templateSmarty = "Smarty" // -> ${7*7} -> a{*comment*}b is a payload that can identify Smarty
		var templateTwig = "Twig"     // -> {{7*'7'}} would result in 49 in Twig
	*/

	templates := []string{templateJinja2, templateMako, templateSmarty, templateTwig}
	possibleEngines := []string{}

	for _, t := range templates {
		u, payloads, results := replaceParameters(url, vulnParamElement, t)
		if u == "" {
			return nil
		}

		ssti, injectionPayloadElements := makeRequest(u, results, quietMode)
		if ssti {
			// if we found a possible ssti, log and store the template that we have possibly identified
			workingPayloads := ""
			for i, wp := range injectionPayloadElements {
				workingPayloads += payloads[wp]

				if i != len(injectionPayloadElements)-1 {
					workingPayloads += "|"
				}
			}

			fmt.Printf("URL: %s -> Parameter Payload: %s -> Engine: %s\n", u, workingPayloads, t)
			possibleEngines = append(possibleEngines, t)
		}
	}

	return possibleEngines
}

// use runes so we aren't just stuck with ASCII incase we have some funky use cases for this
func removeLastRune(s string) string {
	r := []rune(s)
	return string(r[:len(r)-1])
}
