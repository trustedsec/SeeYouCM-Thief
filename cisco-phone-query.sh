#!/bin/bash

# script to query phone models & download webpages for thief.py

phoneiplist=$1
sname=$(basename "$0")
GRN='\x1B[1;32m'
WHT='\x1B[1;37m'
RED='\x1B[1;31m'
CYN='\x1B[1;36m'
YEL='\x1B[1;33m'
NC='\x1B[0m'

# catch termination
trap f_term SIGHUP SIGINT SIGTERM

f_term()
{
	echo -e "\n${RED}[!] ${NC}Caught ${RED}ctrl+c${NC}, removing all tmp files"
	rm rm tmp tmp2 tmp3 tmp4 tmp5 2>/dev/null
	exit 1
}

# script options parsing
if [[ $phoneiplist == '' ]]; then
	echo -e "\n${RED}[!] ${NC}Phone list not provided, try again."
	echo -e "${RED}[!] ${NC}Syntax: ${WHT}${sname} <phone_list>${NC}"
	exit 1
fi

if ! [[ -f $phoneiplist ]]; then
	echo -e "\n${RED}[!] ${WHT}$phoneiplist${NC} does not exist, try again."
	exit 1
fi

# query phone models
echo -e "\n${CYN}[*] ${NC}Getting phone models. . ."
while read phone; do
	curl --silent -k -L http://${phone} > tmp
	model=$(grep -m1 -E -o "\bCP-[A-Za-z0-9]{2,6}\b" tmp)
	if ! [[ $model == '' ]]; then		#ignores cisco communicator soft phones
		echo "$phone,$model" | tee -a tmp2
	fi
done < $phoneiplist

# get unique phone models
sort -t',' -k2 -u tmp2 > tmp3

# download config html page
echo -e "\n${CYN}[*] ${NC}Downloading unique network config pages"
while read line; do
	ipaddr=$(echo $line | cut -d',' -f1)
	model=$(echo $line | cut -d',' -f2)
	curl --silent -k -L http://${ipaddr}/CGI/Java/Serviceability?adapter=device.statistics.device > cisco-${model}.html
	if ! grep -q -i -E 'CUCM Server|Unified CM' cisco-${model}.html; then
		curl --silent -k -L http://${ipaddr}/NetworkConfiguration > cisco-${model}.html
		echo cisco-${model}.html >> tmp4
	fi
	if ! grep -q -i -E 'CUCM Server|Unified CM' cisco-${model}.html; then
		unknownuri=1
		echo "$ipaddr,$model not on known page"
		echo http://${ipaddr} >> tmp5
		rm cisco-${model}.html
	fi
done < tmp3

# tar files or note unkown URI & prompt for manually saving page
if [[ $unknownuri == '1' ]]; then
	echo -e "\n${YEL}[-] ${NC}Found phones with unkown network config URI${NC}"
	echo -e "\tBrowse to the following phone webpage(s) & click [Network Setup] to verify URL"
	echo -e "\tFile > Save As: cisco-${model}.html"
	echo -e "\tNote actual URI to JB when sending html files"
	cat tmp5
	echo -e "\tAlso include the following files when sending to JB:"
	cat tmp4
else
	files2tar=$(cat tmp4)
	filen='ciscophones.tgz'
	tar czf $filen $files2tar
	echo -e "\n${CYN}[*] ${NC}Send the following file to JB: ${WHT}$filen${NC}"

fi

rm tmp tmp2 tmp3 tmp4 tmp5 2>/dev/null
