/*
	Baseboard Management Controller- NVRAM rule 
	This rulset is based on 35C3 - Modchips of the State by Trammell Hudson https://www.youtube.com/watch?time_continue=1&v=C7H3V7tkxeA
	John Franolich
	revision: 20181228
	Also see https://www.codeproject.com/Articles/38226/NvramRestorer-dumping-and-restoring-BIOS-settings
	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/
*/

}
rule NVRAM_shell {
	meta:
		description = "Baseboard Management Controller- NVRAM rule  - Generic Rule - possible script found in BMC zip file"
		author = "John Franolich"
		reference = "Trammell Hudson https://www.youtube.com/watch?time_continue=1&v=C7H3V7tkxeA"
		date = "2018/12/28"
		score = 60
	strings:
		$s0 = .*\.sh$ ascii

	condition:
		$s0

}

