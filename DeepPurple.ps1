<#
DeepPurple.ps1
--------------

John "Fran the Man" Franolich
and his humble sidekick

Note: Keep this in the same directory as:
    DeepBlue.ps1
    whitelist.txt
    regex.txt

#>



param ([string]$file=$env:file,[string]$log=$env:log)   

function ProcessEventsDirDeepDive([string]$file) 
{ 
   
    # Deepblue on the top-level path
    $dirpath = $file + "\*"
    .\DeepBlue $dirpath

    
    foreach ($item in Get-ChildItem $file)
    {
        if ($exclude | Where {$item -like $_}) { continue }

        if (Test-Path $item.FullName -PathType Container) 
        {
            ProcessEventsDirDeepDive($item.FullName)
        } 
    } 
    
    
}
      

function Main 
{   
    ProcessEventsDirDeepDive($file) 
}

. Main



