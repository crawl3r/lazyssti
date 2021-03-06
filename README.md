# lazyssti  
  
A lazy approach to chaining other golang bins together. Not made to replace the likes of qsreplace chains, just another option.  
  
lazyssti attempts to identify the templating engine once a vulnerable parameter has been found. This hasn't been heavily tested in the wild but the logic worked locally on vulnerable apps. Any issues or derps, please let me know!  
  
## Installation  
  
```
go get github.com/crawl3r/lazyssti    
```
  
## Usage   
  
Default:  
```
cat urls.txt | ./lazyssti
```  
  
Quiet mode and saving output:  
```
cat urls.txt | ./lazyssti -q -o wins.txt
```  
  
Ideal to use with tools such as hakrawler, gau, waybackurls etc.  
```
echo "https://hackerone.com" | tools/hakrawler -nocolor | sort -ufd | grep "\[url\]" | while read tag url; do echo $url; done
```  
  
## Thanks  
  
Big thanks to Hakluke, I used Hakrawler's (https://github.com/hakluke/hakrawler) concurrency and picked at the concurrency/goroutine code to patch mine. The speed increase is insane! Who'd have thought that more than 1 thread was faster than a single thread?!   
  
## License  
  
I'm just a simple skid. Licensing isn't a big issue to me, I post things that I find helpful online in the hope that others can:  
A) learn from the code  
B) find use with the code or  
C) need to just have a laugh at something to make themselves feel better  
  
Either way, if this helped you - cool :)  
