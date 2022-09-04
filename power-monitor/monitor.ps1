function Get-PorcessObject{
	$tempArray = New-Object System.Collections.ArrayList
	foreach($i in $(Get-Process | Select-Object -Property ProcessName, Id, Path)){
		$null = $tempArray.add($i)
	}
	return $tempArray
}
while($True){
	$DiffA = Get-PorcessObject
	sleep 0.1
	$DiffB = Get-PorcessObject
	$BreakLine = "-" * 100
	foreach($i in $DiffA){
		if ($DiffB.Id -notcontains $i.Id){
			Write-host $BreakLine
			Write-host "[+] New Process info: "$i -ForegroundColor Green
			Write-host "[+] Try to get net connection via pid: " -ForegroundColor Yellow
			Try {
				Get-NetTcpConnection -OwningProcess $i.Id -ErrorAction Stop
			}
			catch{
				Write-host "[-] Get net connection failed" -ForegroundColor Red
			}
			Write-host $BreakLine
		}
	}
}
