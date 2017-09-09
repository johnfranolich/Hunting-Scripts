# Malware using PowerShell and ADS  https://www.redcanary.com/blog/using-alternate-data-streams-bypass-user-account-controls/
# PowerShell script to find ADS - orginal code from https://obligatorymoniker.wordpress.com/2013/02/11/find-all-files-with-alternate-data-streams/
# to test create a txt files with an ADS > echo "ADS" > test.txt:hidden.txt

gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data' | where stream -ne 'Zone.Identifier'


