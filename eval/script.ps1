# eval/blueteam.py 와 eval/blueteam.ts 실행 환경을 맞추고, 출력이 같은지 대조한다.
# usage: pwsh -File eval/script.ps1
#        powershell -ExecutionPolicy Bypass -File eval/script.ps1
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

function Fail([string]$Message) {
  [Console]::Error.WriteLine($Message)
  exit 2
}

function Refresh-Path {
  $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  $user = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($machine -and $user) {
    $env:Path = "$machine;$user"
  } elseif ($machine) {
    $env:Path = $machine
  } elseif ($user) {
    $env:Path = $user
  }
}

function Test-PythonVersion([string]$Exe, [string[]]$PrefixArgs) {
  $all = @()
  if ($PrefixArgs) { $all += $PrefixArgs }
  $all += @('-c', 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)')
  try {
    & $Exe @all 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Find-Python {
  $candidates = @(
    @{ Cmd = 'python3'; Args = @() },
    @{ Cmd = 'python'; Args = @() },
    @{ Cmd = 'py'; Args = @('-3') }
  )
  foreach ($c in $candidates) {
    $cmd = Get-Command $c.Cmd -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if (Test-PythonVersion $cmd.Source $c.Args) {
      return @{ Exe = $cmd.Source; Args = @($c.Args) }
    }
  }
  return $null
}

function Find-Node {
  $cmd = Get-Command node -ErrorAction SilentlyContinue
  if (-not $cmd) { return $null }
  try {
    $ver = & $cmd.Source -v 2>$null
  } catch {
    return $null
  }
  if (-not $ver) { return $null }
  $trimmed = $ver.ToString().Trim().TrimStart('v')
  $majorStr = ($trimmed -split '\.')[0]
  $major = 0
  if (-not [int]::TryParse($majorStr, [ref]$major)) { return $null }
  if ($major -lt 20) { return $null }
  return $cmd.Source
}

function Install-Winget([string]$Id) {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) { return $false }
  Write-Host "[install] winget install $Id"
  & $winget.Source install -e --id $Id --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { return $false }
  Refresh-Path
  return $true
}

function Invoke-Captured([string]$FilePath, [string[]]$ArgumentList) {
  $stdout = [IO.Path]::GetTempFileName()
  $stderr = [IO.Path]::GetTempFileName()
  try {
    $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
      -WorkingDirectory $Root -NoNewWindow -Wait -PassThru `
      -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $out = [IO.File]::ReadAllText($stdout, [Text.UTF8Encoding]::new($false))
    $err = [IO.File]::ReadAllText($stderr, [Text.UTF8Encoding]::new($false))
    if ($p.ExitCode -ne 0) {
      throw ("{0} exit {1}`n{2}{3}" -f $FilePath, $p.ExitCode, $out, $err)
    }
    return $out
  } finally {
    Remove-Item -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue
  }
}

function Normalize-Text([string]$Text) {
  $n = $Text -replace "`r`n", "`n" -replace "`r", "`n"
  return $n.TrimEnd("`n") + "`n"
}

$py = Find-Python
if (-not $py) {
  if (-not (Install-Winget 'Python.Python.3.12')) {
    Fail 'python >= 3.10 이 필요합니다. Python 을 설치한 뒤 다시 실행하세요.'
  }
  $py = Find-Python
  if (-not $py) { Fail 'python >= 3.10 설치 후에도 찾지 못했습니다.' }
}

$node = Find-Node
if (-not $node) {
  if (-not (Install-Winget 'OpenJS.NodeJS.LTS')) {
    Fail 'node >= 20 이 필요합니다. Node.js 를 설치한 뒤 다시 실행하세요.'
  }
  $node = Find-Node
  if (-not $node) { Fail 'node >= 20 설치 후에도 찾지 못했습니다.' }
}

$tsxCli = Join-Path $Root 'src/ts/node_modules/tsx/dist/cli.mjs'
if (-not (Test-Path -LiteralPath $tsxCli)) {
  $npm = Get-Command npm -ErrorAction SilentlyContinue
  if (-not $npm) { Fail 'npm 이 없습니다. Node.js 설치를 확인하세요.' }
  $tsDir = Join-Path $Root 'src/ts'
  Write-Host '[install] npm --prefix src/ts install'
  & $npm.Source --prefix $tsDir install --no-fund --no-audit
  if ($LASTEXITCODE -ne 0) { Fail 'npm install 이 실패했습니다.' }
  if (-not (Test-Path -LiteralPath $tsxCli)) { Fail "tsx 설치 실패: $tsxCli 가 없습니다." }
}

$pyVerArgs = @()
if ($py.Args) { $pyVerArgs += $py.Args }
$pyVerArgs += @('-c', 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
$pyVer = (& $py.Exe @pyVerArgs).ToString().Trim()
$nodeVer = (& $node -v).ToString().Trim()

Write-Host '== 환경 =='
Write-Host ("python  {0}  ({1})" -f $pyVer, $py.Exe)
Write-Host ("node    {0}  ({1})" -f $nodeVer, $node)
Write-Host ("tsx     {0}" -f $tsxCli)

$importArgs = @()
if ($py.Args) { $importArgs += $py.Args }
$pySrc = Join-Path $Root 'src/python'
$importArgs += @('-c', "import sys; sys.path.insert(0, r'''$pySrc'''); from ko_pii import detect_all")
& $py.Exe @importArgs 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Fail 'ko_pii 를 import 할 수 없습니다. src/python 트리를 확인하세요.'
}
Write-Host ("ko_pii  {0}" -f $pySrc)

$blueteamPy = Join-Path $Root 'eval/blueteam.py'
$blueteamTs = Join-Path $Root 'eval/blueteam.ts'

Write-Host ''
Write-Host '== 실행 =='
Write-Host 'python  eval/blueteam.py'
$runPy = @()
if ($py.Args) { $runPy += $py.Args }
$runPy += $blueteamPy
$pyOut = Invoke-Captured $py.Exe $runPy
Write-Host 'tsx     eval/blueteam.ts'
$tsOut = Invoke-Captured $node @($tsxCli, $blueteamTs)

$pyNorm = Normalize-Text $pyOut
$tsNorm = Normalize-Text $tsOut

Write-Host ''
Write-Host '== 결과 =='
if ($pyNorm -ceq $tsNorm) {
  Write-Host 'IDENTICAL'
  Write-Host ''
  [Console]::Out.Write($pyNorm)
  exit 0
}

Write-Host 'MISMATCH'
Write-Host ''
$pyFile = Join-Path ([IO.Path]::GetTempPath()) 'ko-pii-blueteam-python.txt'
$tsFile = Join-Path ([IO.Path]::GetTempPath()) 'ko-pii-blueteam-ts.txt'
[IO.File]::WriteAllText($pyFile, $pyNorm, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($tsFile, $tsNorm, [Text.UTF8Encoding]::new($false))
$diff = Get-Command diff -ErrorAction SilentlyContinue
$git = Get-Command git -ErrorAction SilentlyContinue
if ($diff) {
  & $diff.Source -u -L python -L typescript $pyFile $tsFile
} elseif ($git) {
  & $git.Source -c core.pager= diff --no-index -- $pyFile $tsFile
} else {
  Write-Host '--- python'
  [Console]::Out.Write($pyNorm)
  Write-Host '+++ typescript'
  [Console]::Out.Write($tsNorm)
}
Remove-Item -LiteralPath $pyFile, $tsFile -ErrorAction SilentlyContinue
exit 1
