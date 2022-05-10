#!/bin/bash

echo -e "
		        ____________     __       _____________ 
	                \_____     /    /_ \      \      _____/
 		          \_____    \____/  \____/     _____/
  		            \_____       Dharma      _____/
    		              \___________  ___________/
           		                /____\
   
"

############################################################### Housekeeping tasks ######################################################################

echo -e "\e[94mEnter the organisation name (E.g., Carbon Black): \e[0m"
read org

cdir=`echo $org | tr '[:upper:]' '[:lower:]'| tr " " "_"`

cwhois=`echo $org | tr " " "+"`


echo -e "\e[94mEnter the root domain name (eg: frogy.com): \e[0m"
read domain_name
echo -e "\e[92mHold on! some house keeping tasks being done... \e[0m"
if [[ -d output ]]
then
        :
else
        mkdir output
fi
if [[ -d output/$cdir ]]
then
        echo -e "\e[94mCreating $org directory in the 'output' folder...\e[0m"
        rm -r -f output/$cdir
        mkdir output/$cdir
	mkdir output/$cdir/raw_output
	mkdir output/$cdir/raw_output/raw_http_responses
	mkdir output/$cdir/dnstemp.txtls
else
        echo -e "\e[94mCreating $org directory in the 'output' folder... \e[0m"
        mkdir output/$cdir
	mkdir output/$cdir/raw_output
	mkdir output/$cdir/raw_output/raw_http_responses
	mkdir output/$cdir/dnstemp.txtls
fi

############################################################### Subdomain enumeration ######################################################################

#################### AMASS ENUMERATION #############################

amass enum -passive -norecursive -nolocaldb -noalts -d $domain_name >> output/$cdir/amass.txtls
cat output/$cdir/amass.txtls | anew >> all.txtls
echo -e "\e[36mAmaas count: \e[32m$(cat output/$cdir/amass.txtls | tr '[:upper:]' '[:lower:]'| anew | wc -l)\e[0m"

#################### WayBackEngine  ENUMERATION ######################
# this code is taken from another open-source project at - https://github.com/bing0o/SubEnum/blob/master/subenum.sh

curl -sk "http://web.archive.org/cdx/search/cdx?url=*."$domain_name"&output=txt&fl=original&collapse=urlkey&page=" | awk -F / '{gsub(/:.*/, "", $3); print $3}' | anew | sort -u >> output/$cdir/wayback.txtls
cat output/$cdir/wayback.txtls >> all.txtls
echo -e "\e[36mWaybackEngine count: \e[32m$(cat output/$cdir/wayback.txtls | tr '[:upper:]' '[:lower:]'| anew | wc -l)\e[0m"

################### BufferOver ENUMERATION #########################
# this code is taken from another open-source project at - https://github.com/bing0o/SubEnum/blob/master/subenum.sh

curl -s "https://dns.bufferover.run/dns?q=."$domain_name"" | grep $domain_name | awk -F, '{gsub("\"", "", $2); print $2}' | anew >> output/$cdir/bufferover.txtls
cat output/$cdir/bufferover.txtls >> all.txtls
echo -e "\e[36mBufferOver Count: \e[32m$(cat output/$cdir/bufferover.txtls | tr '[:upper:]' '[:lower:]'| anew | wc -l)\e[0m"


#################### SUBLIST3R ENUMERATION ######################

python3 Sublist3r/sublist3r.py -d $domain_name -o sublister_output.txt &> /dev/null

if [ -f "sublister_output.txt" ]; then
        cat sublister_output.txt|anew|grep -v " "|grep -v "@" | grep "\." >> output/$cdir/sublister.txtls
        rm sublister_output.txt
	cat output/$cdir/sublister.txtls|anew|grep -v " "|grep -v "@" | grep "\." >> all.txtls
	echo -e "\e[36mSublister count: \e[32m$(cat output/$cdir/sublister.txtls | tr '[:upper:]' '[:lower:]'| anew | wc -l)\e[0m"
else
        echo -e "\e[36mSublister count: \e[32m0\e[0m"
fi

#################### FINDOMAIN ENUMERATION ######################

findomain-linux -t $domain_name -q >> output/$cdir/findomain.txtls
cat output/$cdir/findomain.txtls|anew|grep -v " "|grep -v "@" | grep "\." >> all.txtls
echo -e "\e[36mFindomain count: \e[32m$(cat output/$cdir/findomain.txtls | tr '[:upper:]' '[:lower:]'| anew |grep -v " "|grep -v "@" | grep "\."| wc -l)\e[0m"

#################### GATHERING ROOT DOMAINS ######################

python3 rootdomain.py | cut -d " " -f7 | tr '[:upper:]' '[:lower:]' | anew | sed '/^$/d' | grep -v " "|grep -v "@" | grep "\." >> rootdomain.txtls

#################### DNSCAN ENUMERATION ######################

python3 dnscan/dnscan.py -d %%.$domain_name -w wordlist/subdomains-top1million-5000.txt -D -o output/$cdir/dnstemp.txtls > /dev/null 2>&1
cat output/$cdir/dnstemp.txtls | grep $domain_name | egrep -iv ".(DMARC|spf|=|[*])" | cut -d " " -f1 | anew | sort -u | grep -v " "|grep -v "@" | grep "\." >>  output/$cdir/dnscan.txtls
rm output/$cdir/dnstemp.txtls
echo -e "\e[36mDnscan: \e[32m$(cat output/$cdir/dnscan.txtls | tr '[:upper:]' '[:lower:]'| anew | grep -v " "|grep -v "@" | grep "\." | wc -l)\e[0m"

#################### SUBFINDER2 ENUMERATION ######################

subfinder -dL rootdomain.txtls --silent >> output/$cdir/subfinder2.txtls
echo -e "\e[36mSubfinder count: \e[32m$(cat output/$cdir/subfinder2.txtls | tr '[:upper:]' '[:lower:]'| anew | grep -v " "|grep -v "@" | grep "\."  | wc -l)\e[0m"
cat output/$cdir/subfinder2.txtls | grep "/" | cut -d "/" -f3 | grep -v " "|grep -v "@" | grep "\." >> all.txtls
cat output/$cdir/subfinder2.txtls | grep -v "/" | grep -v " "|grep -v "@" | grep "\."  >> all.txtls

mv rootdomain.txtls output/$cdir/
echo "www.$domain_name" >> all.txtls
echo "$domain_name" >> all.txtls
cat all.txtls | tr '[:upper:]' '[:lower:]'| anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> $cdir.master
mv $cdir.master output/$cdir/$cdir.master
sed -i 's/<br>/\n/g' output/$cdir/$cdir.master
rm all.txtls

#################### SUBDOMAIN RESOLVER ######################

while read d || [[ -n $d ]]; do
  ip=$(dig +short $d|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1)
  if [ -n "$ip" ]; then
    echo "$d,$ip" >>output/$cdir/resolved.txtls
  else
    echo "$d,Can't Resolve" >>output/$cdir/resolved.txtls
  fi
done <output/$cdir/$cdir.master
sort output/$cdir/resolved.txtls | uniq > output/$cdir/resolved.new
mv output/$cdir/resolved.new output/$cdir/resolved.txtls


############################################################################# FINDING LOGIN PORTALS  ##################################################################

portlst=`naabu -l output/$cdir/$cdir.master -pf ports -silent | cut -d ":" -f2 | anew | tr "\n" "," | sed 's/.$//'` &> /dev/null

httpx -silent -l output/$cdir/$cdir.master -p $portlst -fr -include-chain -store-chain -sc -tech-detect -server -title -cdn -cname -probe -srd output/$cdir/raw_http_responses/ -o output/$cdir/temp_live.txtls &> /dev/null

cat output/$cdir/temp_live.txtls | grep SUCCESS | cut -d "[" -f1 >> output/$cdir/livesites.txtls

cat output/$cdir/temp_live.txtls | grep SUCCESS >> output/$cdir/technology.txtls

rm -f output/$cdir/temp_live.txtls

while read lf; do
        loginfound=`curl -s -L $lf | grep 'type="password"'`
        if [ -z "$loginfound" ]
                then
                :
        else
                echo "$lf" >> output/$cdir/loginfound.txtls
        fi

done <output/$cdir/livesites.txtls


echo -e "\e[93mTotal live websites (on all available ports) found: \e[32m$(cat output/$cdir/livesites.txtls | tr '[:upper:]' '[:lower:]' | anew | wc -l)\e[0m"

if [[ -f "output/$cdir/loginfound.txtls" ]]
	then
		echo -e "\e[93mTotal login portals found: \e[32m$(cat output/$cdir/loginfound.txtls | tr '[:upper:]' '[:lower:]' | anew| wc -l)\e[0m"
		mv output/$cdir/loginfound.txtls output/$cdir/raw_output
	else
		echo -e "\e[93mTotal login portals found: \e[32m0\e[0m"
fi

echo -e "\e[36mFinal output has been generated in the output/$cdir/ folder: \e[32moutput.csv\e[0m"

cat output/$cdir/resolved.txtls | cut -d ',' -f1 >> temp1.txt
cat output/$cdir/resolved.txtls | cut -d ',' -f2 >> temp2.txt

if [ -f output/$cdir/loginfound.txtls ]; then
	paste -d ','  output/$cdir/rootdomain.txtls temp1.txt temp2.txt output/$cdir/livesites.txtls output/$cdir/loginfound.txtls | sed '1 i \Root Domain,Subdomain,IP Address,Live Website,Login Portals' > output/$cdir/output.csv

else
	paste -d ','  output/$cdir/rootdomain.txtls temp1.txt temp2.txt output/$cdir/livesites.txtls | sed '1 i \Root Domain,Subdomain,IP Address,Live Website' > output/$cdir/output.csv
fi
#################### Waybackurls enumartion ##############
echo "Scraping wayback for data..."
cat ./output/$cdir/livesites.txtls | waybackurls > output/$cdir/wayback-data/urls.txtls
cat ./output/$cdir/wayback-data/urls.txtls  | sort -u | unfurl --unique keys > ./output/$cdir/wayback-data/paramlist.txt
[ -s ./output/$cdir/wayback-data/paramlist.txt ] && echo "Wordlist saved to /$domain/$foldername/wayback-data/paramlist.txt"

cat ./output/$cdir/wayback-data/urls.txtls  | sort -u | grep -P "\w+\.js(\?|$)" | sort -u > ./output/$cdir/wayback-data/jsurls.txt
[ -s ./output/$cdir/wayback-data/jsurls.txt ] && echo "JS Urls saved to /output/$cdir/wayback-data/jsurls.txt"

cat ./output/$cdir/wayback-data/urls.txtls  | sort -u | grep -P "\w+\.php(\?|$) | sort -u " > ./output/$cdir//wayback-data/phpurls.txt
[ -s ./output/$cdir/wayback-data/phpurls.txt ] && echo "PHP Urls saved to /output/$cdir/wayback-data/phpurls.txt"

cat ./output/$cdir/wayback-data/urls.txtls  | sort -u | grep -P "\w+\.aspx(\?|$) | sort -u " > ./output/$cdir/wayback-data/aspxurls.txt
[ -s ./output/$cdir/wayback-data/aspxurls.txt ] && echo "ASP Urls saved to /output/$cdir/wayback-data/aspxurls.txt"

cat ./output/$cdir/wayback-data/urls.txtls  | sort -u | grep -P "\w+\.jsp(\?|$) | sort -u " > ./output/$cdir/wayback-data/jspurls.txt
[ -s ./output/$cdir/wayback-data/jspurls.txt ] && echo "JSP Urls saved to /output/$cdir/wayback-data/jspurls.txt"
}

rm temp1.txt temp2.txt
echo -e "\e[93mTotal unique subdomains found: \e[32m$(cat output/$cdir/$cdir.master | tr '[:upper:]' '[:lower:]'| anew  | wc -l)\e[0m"
echo -e "\e[93mTotal unique resolved subdomains found: \e[32m$(cat output/$cdir/resolved.txtls | grep -v "Can't" | wc -l) \e[0m"
echo -e "\e[93mTotal unique root domains found: \e[32m$(cat output/$cdir/rootdomain.txtls | tr '[:upper:]' '[:lower:]'|anew | wc -l)\e[0m"
cat output/$cdir/rootdomain.txtls | tr '[:upper:]' '[:lower:]' | anew
mv output/$cdir/*.txtls output/$cdir/raw_output
mv output/$cdir/raw_output/rootdomain.txtls output/$cdir/
mv output/$cdir/raw_output/resolved.txtls output/$cdir/
mv output/$cdir/raw_output/livesites.txtls output/$cdir/
mv output/$cdir/raw_output/loginfound.txtls output/$cdir/
