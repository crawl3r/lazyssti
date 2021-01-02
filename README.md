# lazyssti  
  
A lazy approach to chaining other golang bins together. Not made to replace the likes of qsreplace chains, just another option.  
  
### Installation  
  
```
go get github.com/crawl3r/lazyssti    
```
  
### Usage   
  
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
  
### License  
  
I'm just a simple skid. Licensing isn't a big issue to me, I post things that I find helpful online in the hope that others can:  
A) learn from the code  
B) find use with the code or  
C) need to just have a laugh at something to make themselves feel better  
  
Either way, if this helped you - cool :)  