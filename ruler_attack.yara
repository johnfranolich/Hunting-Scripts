rule Check_ruler_attack

{

	meta:

		Author = "Franolich"

		Description = "Checks for ruler attack typically requires the use of WebDav for payload delivery. WebDav writes to disk, and this location should be monitored https://sensepost.com/blog/2017/notruler-turning-offence-into-defence/"

	

	strings:

		$key = "%systemdrive%\windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore" 


	condition:

		all of them

}