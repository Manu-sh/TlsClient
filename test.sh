#!/bin/bash

# invoke with -s to disable ansi color
[ "$1" == "-s" ] && NO_ANSI_ESC=true || NO_ANSI_ESC=false

ANSI_SHOW_CUR="\033[?25h"
ANSI_HIDE_CUR="\033[?25l"
ANSI_RESET="\033[0m"
ANSI_RED="\033[31m"
ANSI_GREEN="\033[32m"

# set time format
# TIMEFORMAT=%R;

trap 'echo -e "${ANSI_RESET}${ANSI_SHOW_CUR}"; exit 0' 2

# simulate a matrix
HOSTS=(
        "expired.badssl.com"          "B"
        "wrong.host.badssl.com"       "B"
        "self-signed.badssl.com"      "B"
        "untrusted-root.badssl.com"   "B"
        "revoked.badssl.com"          "B"
        "no-common-name.badssl.com"   "B"
        "no-subject.badssl.com"       "B"
        "incomplete-chain.badssl.com" "B"
        "edellroot.badssl.com"        "B"
        "sha1-2016.badssl.com"        "B"
        "google.com"                  "G"
        "youtube.com"                 "G"
        "facebook.com"                "G"
)

# index, exit code
pstat() {
	[ -z $1 ] && echo "index required" && exit 2
	[ -z $2 ] && echo "exit code required" && exit 2

	# access to 2nd columns
	if ([ $2 -ne 0 ] && [ "${HOSTS[$1+1]}" == "B" ]) || ([ $2 -eq 0 ] && [ "${HOSTS[$1+1]}" == "G" ]); then
		return 0
	else
		return 1
	fi
}

# subject of test, success, failure
echoStat() {
	local ecode=$?
	if ! $NO_ANSI_ESC; then
		! pstat $i $ecode && echo -ne "${1}\033[41;G${ANSI_RED}[${2}]${ANSI_RESET}" || echo -ne "${1}\033[41;G${ANSI_GREEN}[${3}]${ANSI_RESET}"
	else
	 	! pstat $i $ecode && printf "%-35s %-40s %s" "${1}" "${2}" "[BAD]" || printf "%-35s %-40s %s" "${1}" "${3}" "[OK]"
	fi
}

# check for dependencies
for i in "wget" "curl" "ruby" "python3"; do
	! [ -e "$(which $i 2>/dev/null)" ] && echo "$i required" && exit 2
done

! [ -e "./main" ] || ! [ -e "./main0" ] && echo "type make main{,0}" && exit 2

! $NO_ANSI_ESC && echo -e "$ANSI_HIDE_CUR"
for ((i=0; i < ${#HOSTS[@]}; i++)); do

	# ignore 2nd columns here
	(($i%2)) && continue # i%2 -eq 0
	cur=${HOSTS[$i]}

	echo "===================================================================================="
	./main0 $cur &>/dev/null
	echoStat "$cur" "ClientTls" "ClientTls"
	echo

	./main $cur &>/dev/null
	echoStat "$cur" "TlsClient" "TlsClient"
	echo

	./https.rb "https://$cur" &>/dev/null
	echoStat "$cur" "Ruby" "Ruby"
	echo

	./https.py "$cur" &>/dev/null
	echoStat "$cur" "Python" "Python"
	echo

	curl -s "https://${cur}" &>/dev/null
	echoStat "$cur" "cURL" "cURL"
	echo

	wget -O- "https://${cur}" &>/dev/null
	echoStat "$cur" "Wget" "Wget"
	echo -ne "$T\n"
	echo "===================================================================================="
done
! $NO_ANSI_ESC && echo -ne "${ANSI_RESET}${ANSI_SHOW_CUR}"; exit 0
