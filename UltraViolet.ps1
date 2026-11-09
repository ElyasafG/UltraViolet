#Requires -Version 5.1
<#
.SYNOPSIS
    UltraViolet - Purple-team CLI session recorder.

.DESCRIPTION
    Interactive, menu-driven recorder for authorised cloud assessment sessions.
    Wraps a PowerShell REPL, executes the operator's commands in-process (state,
    variables and CWD persist), and journals every command with the metadata a
    blue team needs to correlate against CloudTrail / Azure Activity Log /
    Entra sign-in logs.

    Storage model:
      <DataRoot>\<yyyy-MM-dd HH-mm-ss> - <Name>.jsonl        write-ahead journal (source of truth)
      <DataRoot>\<yyyy-MM-dd HH-mm-ss> - <Name>.meta.json    session metadata
      <DataRoot>\<yyyy-MM-dd HH-mm-ss> - <Name>.xlsx         rendered workbook
      <DataRoot>\<yyyy-MM-dd HH-mm-ss> - <Name>.outputs\     full outputs > 30k chars

    The JSONL journal is flushed after every command, so a crash / lost RDP
    session never costs more than the in-flight command. The XLSX is re-rendered
    from the journal on session exit, on ":sync", and every 10 commands.

.PARAMETER DataRoot
    Where sessions are stored. Default: <Documents>\UltraViolet\Sessions

.PARAMETER NoTheme
    Skip the UltraViolet (#A100FF) console theme (useful when piping or in constrained hosts).

.NOTES
    Scope: this tool only records what the operator types. It performs no
    scanning, no credential access and no traffic of its own beyond an optional,
    opt-in egress-IP lookup. Use only within an authorised engagement.
#>

[CmdletBinding()]
param(
    [string]$DataRoot = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'UltraViolet\Sessions'),
    [switch]$NoTheme
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ============================================================================
#  CONSTANTS
# ============================================================================

$script:ESC          = [char]27
$script:AppName      = 'UltraViolet'
$script:AppVersion   = '1.3.0'
$script:SchemaVer    = 1
$script:DataRoot     = $DataRoot
$script:UseTheme     = -not $NoTheme
$script:VT           = $false
$script:OrigBg       = 'Black'
$script:OrigFg       = 'Gray'
$script:OrigSlot5    = $null
$script:LastRejected = @()
$script:InputRgb     = '255;196;0'   # #FFC400 - typed command text, bold
# Commands that must own the console (prompts / TUIs). Prefix any other command
# with ":raw " to force the same behaviour.
$script:InteractiveRx = @(
    '^\s*(ssh|scp|sftp|telnet|ftp|nslookup|winrs|mysql|psql|sqlcmd|kubectl\s+exec)\b'
    '^\s*(vi|vim|nano|less|more|top|htop|man)\b'
    '^\s*(python|python3|node|irb|pwsh|powershell|cmd)\s*$'
    '^\s*aws\s+configure\s*$'
    '^\s*aws\s+configure\s+(sso|import|list-profiles)\s*$'
    '^\s*Enter-PSSession\b'
) -join '|'
$script:BrandR       = 161   # #A100FF
$script:BrandG       = 0
$script:BrandB       = 255
$script:MaxCellChars = 30000
# Workbook is re-rendered after every recorded command; the journal is the
# source of truth, the XLSX is a derived view that must never lag behind it.

# Ordered schema: Field -> Excel header. Order defines column order.
$script:Schema = [ordered]@{
    RowId       = '#'
    LocalTime   = 'Local Time'
    UtcTime     = 'UTC Time'
    Command     = 'Command'
    Result      = 'Result'
    Reason      = 'Reason'
    Output      = 'Output'
    SrcIP       = 'Source IP'
    SrcPort     = 'Source Port'
    DstIP       = 'Destination IP'
    DstPort     = 'Destination Port'
    LogonType   = 'Logon Type'
    Api         = 'API Used'
    Intention   = 'Intention'
    Cloud       = 'Cloud'
    Principal   = 'Principal'
    AuthType    = 'Auth Type'
    Attack      = 'ATT&CK'
    ExitCode    = 'Exit Code'
    DurationMs  = 'Duration (ms)'
    Hostname    = 'Host'
    OsUser      = 'OS User'
    OutputFile  = 'Output File'
    Notes       = 'Notes'
}

# Approximate column widths (Excel char units), same order as schema.
$script:ColWidths = @(6, 19, 19, 62, 9, 40, 70, 16, 11, 16, 11, 22, 34, 46, 8, 34, 18, 30, 10, 13, 18, 22, 26, 34)

# Fields the Edit menu allows changing.
$script:EditableFields = @(
    'LocalTime','UtcTime','Command','Result','Reason','Output','SrcIP','SrcPort',
    'DstIP','DstPort','LogonType','Api','Intention','Cloud','Principal','AuthType',
    'Attack','ExitCode','Notes'
)

# ============================================================================
#  CONSOLE THEME  (#A100FF background / white text)
# ============================================================================

function Initialize-ConsoleInterop {
    if ('UltraViolet.Native' -as [type]) { return }
    $code = @'
using System;
using System.Runtime.InteropServices;
namespace UltraViolet {
  [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X; public short Y; }
  [StructLayout(LayoutKind.Sequential)] public struct SMALL_RECT { public short Left; public short Top; public short Right; public short Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct CONSOLE_SCREEN_BUFFER_INFO_EX {
    public int cbSize;
    public COORD dwSize;
    public COORD dwCursorPosition;
    public ushort wAttributes;
    public SMALL_RECT srWindow;
    public COORD dwMaximumWindowSize;
    public ushort wPopupAttributes;
    public bool bFullscreenSupported;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)] public uint[] ColorTable;
  }
  public static class Native {
    const int STD_OUTPUT_HANDLE = -11;
    const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetConsoleMode(IntPtr h, out uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleMode(IntPtr h, uint mode);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
      static extern bool GetConsoleScreenBufferInfoEx(IntPtr h, ref CONSOLE_SCREEN_BUFFER_INFO_EX info);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
      static extern bool SetConsoleScreenBufferInfoEx(IntPtr h, ref CONSOLE_SCREEN_BUFFER_INFO_EX info);

    public static bool EnableVT() {
      try {
        IntPtr h = GetStdHandle(STD_OUTPUT_HANDLE);
        uint mode;
        if (!GetConsoleMode(h, out mode)) return false;
        if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) return true;
        return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
      } catch { return false; }
    }

    // Read a legacy palette slot so it can be restored later. 0xFFFFFFFF = failed.
    public static uint GetPaletteSlot(int slot) {
      try {
        IntPtr h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO_EX info = new CONSOLE_SCREEN_BUFFER_INFO_EX();
        info.cbSize = Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFO_EX));
        if (!GetConsoleScreenBufferInfoEx(h, ref info)) return 0xFFFFFFFF;
        return info.ColorTable[slot];
      } catch { return 0xFFFFFFFF; }
    }

    // Remap a legacy palette slot so conhost can render an exact RGB value.
    public static bool RemapPaletteSlotRaw(int slot, uint colorRef) {
      try {
        IntPtr h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO_EX info = new CONSOLE_SCREEN_BUFFER_INFO_EX();
        info.cbSize = Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFO_EX));
        if (!GetConsoleScreenBufferInfoEx(h, ref info)) return false;
        info.ColorTable[slot] = colorRef;
        info.srWindow.Right  = (short)(info.srWindow.Right  + 1);
        info.srWindow.Bottom = (short)(info.srWindow.Bottom + 1);
        return SetConsoleScreenBufferInfoEx(h, ref info);
      } catch { return false; }
    }

    public static bool RemapPaletteSlot(int slot, byte r, byte g, byte b) {
      try {
        IntPtr h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO_EX info = new CONSOLE_SCREEN_BUFFER_INFO_EX();
        info.cbSize = Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFO_EX));
        if (!GetConsoleScreenBufferInfoEx(h, ref info)) return false;
        info.ColorTable[slot] = (uint)(r | (g << 8) | (b << 16));
        // Known Win32 quirk: SetConsoleScreenBufferInfoEx shrinks the window by 1.
        info.srWindow.Right  = (short)(info.srWindow.Right  + 1);
        info.srWindow.Bottom = (short)(info.srWindow.Bottom + 1);
        return SetConsoleScreenBufferInfoEx(h, ref info);
      } catch { return false; }
    }
  }
}
'@
    try { Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop } catch { }
}

function Set-UltraVioletTheme {
    if (-not $script:UseTheme) { return }
    Initialize-ConsoleInterop

    try {
        $script:OrigBg = $Host.UI.RawUI.BackgroundColor
        $script:OrigFg = $Host.UI.RawUI.ForegroundColor
    } catch { $script:OrigBg = 'Black'; $script:OrigFg = 'Gray' }

    if ('UltraViolet.Native' -as [type]) {
        try { $script:VT = [UltraViolet.Native]::EnableVT() } catch { $script:VT = $false }
        # conhost fallback: repaint DarkMagenta as #A100FF, remembering the original.
        try {
            $prev = [UltraViolet.Native]::GetPaletteSlot(5)
            if ($prev -ne [uint32]::MaxValue) { $script:OrigSlot5 = $prev }
            [void][UltraViolet.Native]::RemapPaletteSlot(5, $script:BrandR, $script:BrandG, $script:BrandB)
        } catch { }
    }
    if (-not $script:VT -and $env:WT_SESSION) { $script:VT = $true }
    if (-not $script:VT -and $PSVersionTable.PSVersion.Major -ge 6) { $script:VT = $true }

    try {
        $Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
        $Host.UI.RawUI.ForegroundColor = 'White'
    } catch { }

    Clear-Screen
}

function Get-Sgr {
    param([string]$Style = 'Text')
    $fg = switch ($Style) {
        'Dim'    { '221;200;255' }
        'Ok'     { '150;255;185' }
        'Warn'   { '255;226;140' }
        'Err'    { '255;145;145' }
        'Cmd'    { $script:InputRgb }
        'Accent' { '255;242;170' }
        default  { '255;255;255' }
    }
    # 'Cmd' (the line you are typing) is bold; everything else resets intensity
    # so bold never leaks into subsequent writes.
    $weight = if ($Style -eq 'Cmd') { '1' } else { '22' }
    return "$($script:ESC)[$weight" + 'm' +
           "$($script:ESC)[48;2;$($script:BrandR);$($script:BrandG);$($script:BrandB)m" +
           "$($script:ESC)[38;2;$fg" + 'm'
}

function Write-T {
    # Both parameters carry an explicit Position. Declaring Position on only
    # ONE parameter silently turns off implicit positional binding for the
    # rest, which breaks every "Write-T 'text' 'Style'" call site.
    param(
        [Parameter(Position = 0)][string]$Text = '',
        [Parameter(Position = 1)][ValidateSet('Text','Dim','Ok','Warn','Err','Cmd','Accent')][string]$Style = 'Text',
        [switch]$NoNewline
    )
    if ($script:VT -and $script:UseTheme) {
        $s = (Get-Sgr $Style) + $Text
        if ($NoNewline) { [Console]::Write($s) } else { [Console]::WriteLine($s) }
    }
    else {
        $c = switch ($Style) {
            'Dim'    { 'Gray' }
            'Ok'     { 'Green' }
            'Warn'   { 'Yellow' }
            'Err'    { 'Red' }
            'Cmd'    { 'DarkYellow' }
            'Accent' { 'Yellow' }
            default  { 'White' }
        }
        if ($NoNewline) { Write-Host $Text -ForegroundColor $c -NoNewline }
        else            { Write-Host $Text -ForegroundColor $c }
    }
}

function Reset-ThemeSgr {
    # External binaries emit their own SGR resets; re-assert ours afterwards.
    if ($script:VT -and $script:UseTheme) { [Console]::Write((Get-Sgr 'Text')) }
}

function Clear-Screen {
    if ($script:VT -and $script:UseTheme) {
        [Console]::Write((Get-Sgr 'Text') + "$($script:ESC)[2J$($script:ESC)[H")
    }
    else {
        try { Clear-Host } catch { }
    }
}

function Restore-Console {
    if ($script:VT -and $script:UseTheme) { [Console]::Write("$($script:ESC)[0m") }
    try {
        $Host.UI.RawUI.BackgroundColor = $script:OrigBg
        $Host.UI.RawUI.ForegroundColor = $script:OrigFg
    } catch { }
    # Put the conhost palette back, otherwise the parent cmd window stays violet.
    if ($null -ne $script:OrigSlot5 -and ('UltraViolet.Native' -as [type])) {
        try { [void][UltraViolet.Native]::RemapPaletteSlotRaw(5, [uint32]$script:OrigSlot5) } catch { }
    }
    # Clear so no cells remain painted with the brand attribute. The session
    # transcript lives in the journal / workbook, not the scrollback.
    try { Clear-Host } catch { }
}

function Set-WindowTitle {
    param([string]$Suffix = '')
    try {
        $t = "[ULTRA-VIOLET] $($script:AppName) $($script:AppVersion)"
        if ($Suffix) { $t += " - $Suffix" }
        $Host.UI.RawUI.WindowTitle = $t
    } catch { }
}

# Splash art. Single-quoted here-string: no escaping, rendered verbatim.
$script:BannerArt = @'
  _   _ _ _             _   _ _       _      _   
 | | | | | |           | | | (_)     | |    | |  
 | | | | | |_ _ __ __ _| | | |_  ___ | | ___| |_ 
 | | | | | __| '__/ _` | | | | |/ _ \| |/ _ \ __|
 | |_| | | |_| | | (_| \ \_/ / | (_) | |  __/ |_ 
  \___/|_|\__|_|  \__,_|\___/|_|\___/|_|\___|\__|
                                                 
                                                                
'@ -split "`r?`n"

function Write-Banner {
    param([string]$Subtitle = '')
    Clear-Screen
    Write-T ''
    foreach ($artLine in $script:BannerArt) { Write-T $artLine 'Accent' }
    Write-T "  $($script:AppName) $($script:AppVersion)  -  Purple-team CLI session recorder" 'Text'
    Write-T '  RECORDING WRAPPER ACTIVE - every command in this window is journalled' 'Dim'
    if ($Subtitle) { Write-T "  $Subtitle" 'Ok' }
    Write-T '  ===============================================================================' 'Accent'
    Write-T ''
}

# ============================================================================
#  LINE EDITOR (history-aware, works with the VT theme)
# ============================================================================

$script:History = New-Object System.Collections.Generic.List[string]

function Read-CommandLine {
    param([string]$Prompt = '> ')

    if (-not $script:VT -or -not $script:UseTheme) {
        Write-T $Prompt 'Accent' -NoNewline
        return [Console]::ReadLine()
    }

    $Prompt = $Prompt -replace "[`r`n]", ' '
    $buffer = New-Object System.Text.StringBuilder
    $pos    = 0
    $hIndex = $script:History.Count
    $stash  = ''

    $render = {
        $text = $buffer.ToString()
        $offset = 0
        try { $winW = [Console]::WindowWidth } catch { $winW = 120 }
        $avail = $winW - $Prompt.Length - 2
        if ($avail -lt 10) { $avail = 10 }
        if ($text.Length -gt $avail) {
            # Scroll the visible window so the caret stays on screen.
            $offset = [Math]::Max(0, $pos - $avail + 1)
            if ($offset + $avail -gt $text.Length) { $offset = [Math]::Max(0, $text.Length - $avail) }
            $text = $text.Substring($offset, [Math]::Min($avail, $text.Length - $offset))
        }
        [Console]::Write("$($script:ESC)[?25l")                       # hide cursor
        [Console]::Write("`r" + (Get-Sgr 'Text') + "$($script:ESC)[2K")
        [Console]::Write((Get-Sgr 'Accent') + $Prompt + (Get-Sgr 'Cmd') + $text)
        $col = $Prompt.Length + ($pos - $offset) + 1
        [Console]::Write("`r" + "$($script:ESC)[$col" + 'G')
        [Console]::Write("$($script:ESC)[?25h")                       # show cursor
    }

    # Ctrl+C must reach the line editor, but only here - once a command is
    # running, Ctrl+C has to go back to being a real interrupt.
    $prevCtrlC = $false
    try { $prevCtrlC = [Console]::TreatControlCAsInput; [Console]::TreatControlCAsInput = $true } catch { }

    try {
    & $render
    while ($true) {
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'Enter' {
                [Console]::Write("$($script:ESC)[?25h")
                [Console]::WriteLine()
                $line = $buffer.ToString()
                if ($line.Trim()) {
                    if ($script:History.Count -eq 0 -or $script:History[$script:History.Count - 1] -ne $line) {
                        [void]$script:History.Add($line)
                    }
                }
                return $line
            }
            'Backspace' { if ($pos -gt 0) { [void]$buffer.Remove($pos - 1, 1); $pos-- } }
            'Delete'    { if ($pos -lt $buffer.Length) { [void]$buffer.Remove($pos, 1) } }
            'LeftArrow' { if ($pos -gt 0) { $pos-- } }
            'RightArrow'{ if ($pos -lt $buffer.Length) { $pos++ } }
            'Home'      { $pos = 0 }
            'End'       { $pos = $buffer.Length }
            'Escape'    { [void]$buffer.Clear(); $pos = 0 }
            'UpArrow' {
                if ($script:History.Count -gt 0 -and $hIndex -gt 0) {
                    if ($hIndex -eq $script:History.Count) { $stash = $buffer.ToString() }
                    $hIndex--
                    [void]$buffer.Clear(); [void]$buffer.Append($script:History[$hIndex]); $pos = $buffer.Length
                }
            }
            'DownArrow' {
                if ($hIndex -lt $script:History.Count) {
                    $hIndex++
                    [void]$buffer.Clear()
                    if ($hIndex -eq $script:History.Count) { [void]$buffer.Append($stash) }
                    else { [void]$buffer.Append($script:History[$hIndex]) }
                    $pos = $buffer.Length
                }
            }
            'Tab' { [void]$buffer.Insert($pos, '  '); $pos += 2 }
            default {
                if ($key.Modifiers -band [ConsoleModifiers]::Control) {
                    if ($key.Key -eq 'C') {
                        [Console]::WriteLine()
                        return ''
                    }
                    if ($key.Key -eq 'U') { [void]$buffer.Clear(); $pos = 0 }
                }
                elseif ($key.KeyChar -and [int]$key.KeyChar -ge 32) {
                    [void]$buffer.Insert($pos, $key.KeyChar); $pos++
                }
            }
        }
        & $render
    }
    }
    finally {
        try { [Console]::TreatControlCAsInput = $prevCtrlC } catch { }
    }
}

# True unless the code is only syntactically incomplete (open block/quote/
# here-string, trailing pipe, etc.) - i.e. more lines are expected. A genuine
# syntax error that is NOT incomplete counts as complete so it executes and the
# failure is recorded rather than trapping the operator in a continuation loop.
function Test-InputComplete {
    param([string]$Code)
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$tokens, [ref]$errors)
    if ($errors) {
        foreach ($e in $errors) { if ($e.IncompleteInput) { return $false } }
    }
    return $true
}

# Keep reading continuation lines until the accumulated command parses as a
# complete statement. A trailing backtick forces continuation. An empty line or
# Ctrl+C ends the block early.
function Read-ContinuedCommandLine {
    param([string]$First)
    $acc = $First
    while ($true) {
        $trimEnd  = $acc.TrimEnd()
        $backtick = $trimEnd.EndsWith('`')
        if (-not $backtick -and (Test-InputComplete $acc)) { break }
        $next = Read-CommandLine -Prompt '>> '
        if ([string]::IsNullOrEmpty($next)) { break }
        if ($backtick) {
            # Explicit line continuation: drop the backtick and join with a
            # single space so the two physical lines read as one logical command
            # line. Joining with a newline instead would either bind the newline
            # into the preceding argument or split a native command's args into
            # an invalid separate statement.
            $acc = $trimEnd.Substring(0, $trimEnd.Length - 1).TrimEnd() + ' ' + $next
        }
        else {
            # Structural continuation (open block/quote/here-string): the newline
            # is significant inside those constructs, so keep it.
            $acc = "$acc`n$next"
        }
    }
    # Strip a dangling backtick left by an aborted continuation so the command
    # still parses instead of failing on the trailing line-continuation.
    return ($acc -replace '`\s*$', '')
}

function Read-Answer {
    param([string]$Prompt, [string]$Default = '')
    Write-T $Prompt 'Accent' -NoNewline
    $v = [Console]::ReadLine()
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Confirm-YesNo {
    param([string]$Question, [bool]$DefaultYes = $false)
    $hint = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        Write-T "  $Question $hint " 'Warn' -NoNewline
        $a = [Console]::ReadLine()
        if ([string]::IsNullOrWhiteSpace($a)) { return $DefaultYes }
        switch -Regex ($a.Trim()) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-T '  Please answer y or n.' 'Err' }
        }
    }
}

function Pause-Key {
    param([string]$Msg = 'Press any key to continue...')
    Write-T ''
    Write-T "  $Msg" 'Dim'
    [void][Console]::ReadKey($true)
}

# ============================================================================
#  UTILITIES
# ============================================================================

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid -contains $ch) { [void]$sb.Append('_') } else { [void]$sb.Append($ch) }
    }
    $out = $sb.ToString().Trim()
    if (-not $out) { $out = 'Session' }
    if ($out.Length -gt 60) { $out = $out.Substring(0, 60).Trim() }
    return $out
}

function Remove-AnsiAndControl {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = [regex]::Replace($Text, "$([char]27)\[[0-9;?]*[ -/]*[@-~]", '')
    $t = [regex]::Replace($t, "$([char]27)\][^$([char]7)]*$([char]7)", '')
    $t = [regex]::Replace($t, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
    return $t
}

function ConvertTo-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = Remove-AnsiAndControl $Text
    $t = $t.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    return $t
}

function ConvertTo-XmlAttr {
    param([string]$Text)
    return (ConvertTo-XmlText $Text).Replace('"', '&quot;')
}

function Test-PrivateIp {
    param([string]$Ip)
    if (-not $Ip) { return $true }
    if ($Ip -eq '0.0.0.0' -or $Ip -eq '::' -or $Ip -eq '::1') { return $true }
    if ($Ip -match '^127\.')      { return $true }
    if ($Ip -match '^10\.')       { return $true }
    if ($Ip -match '^192\.168\.') { return $true }
    if ($Ip -match '^169\.254\.') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($Ip -match '^(fe80|fc|fd)') { return $true }
    return $false
}

function Format-Stamp {
    param([datetime]$Dt)
    return $Dt.ToString('dd/MM/yy HH:mm:ss')
}

# ============================================================================
#  HOST / IDENTITY CONTEXT
# ============================================================================

function Get-WindowsLogonType {
    $map = @{
        0 = 'System'; 2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'
        7 = 'Unlock'; 8 = 'NetworkCleartext'; 9 = 'NewCredentials'
        10 = 'RemoteInteractive'; 11 = 'CachedInteractive'
    }
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        $ls   = Get-CimAssociatedInstance -InputObject $proc -ResultClassName Win32_LogonSession -ErrorAction Stop |
                Select-Object -First 1
        if ($ls) {
            $lt = [int]$ls.LogonType
            $nm = if ($map.ContainsKey($lt)) { $map[$lt] } else { 'Unknown' }
            return "$lt ($nm)"
        }
    } catch { }
    if ($env:SESSIONNAME -like 'RDP-*') { return '10 (RemoteInteractive)' }
    if ($env:SESSIONNAME -eq 'Console') { return '2 (Interactive)' }
    return 'Unknown'
}

function Get-CloudAuthContext {
    # Local-only inspection: reads config/token caches. No network calls.
    $ctx = [ordered]@{
        AwsPrincipal = ''; AwsAuthType = ''
        AzPrincipal  = ''; AzAuthType  = ''
        AwsRegion    = ''
    }

    # ---- AWS ----
    try {
        $ctx.AwsRegion = if ($env:AWS_REGION) { $env:AWS_REGION }
                         elseif ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION }
                         else { '' }
        $profileName = if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { 'default' }
        $ctx.AwsPrincipal = "profile=$profileName"

        if ($env:AWS_SESSION_TOKEN)    { $ctx.AwsAuthType = 'Temporary credentials (STS session / assumed role)' }
        elseif ($env:AWS_ACCESS_KEY_ID){ $ctx.AwsAuthType = 'Static access key (environment)' }

        $awsCfg = Join-Path $env:USERPROFILE '.aws\config'
        if (Test-Path $awsCfg) {
            $cfg = Get-Content $awsCfg -Raw -ErrorAction SilentlyContinue
            if ($cfg -match 'sso_start_url|sso_session') { if (-not $ctx.AwsAuthType) { $ctx.AwsAuthType = 'IAM Identity Center (SSO)' } }
            elseif ($cfg -match 'role_arn')              { if (-not $ctx.AwsAuthType) { $ctx.AwsAuthType = 'Assumed role (config role_arn)' } }
            if (-not $ctx.AwsRegion -and $cfg -match '(?m)^\s*region\s*=\s*(\S+)') { $ctx.AwsRegion = $Matches[1] }
        }
        $awsCred = Join-Path $env:USERPROFILE '.aws\credentials'
        if (-not $ctx.AwsAuthType -and (Test-Path $awsCred)) { $ctx.AwsAuthType = 'Static access key (shared credentials file)' }
    } catch { }

    # ---- Azure ----
    try {
        $azProf = Join-Path $env:USERPROFILE '.azure\azureProfile.json'
        if (Test-Path $azProf) {
            $raw = Get-Content $azProf -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            $raw = $raw -replace "^\uFEFF", ''
            $j = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            $sub = $null
            if ($j -and $j.subscriptions) { $sub = $j.subscriptions | Where-Object { $_.isDefault } | Select-Object -First 1 }
            if ($sub) {
                $uname = ''
                $utype = ''
                if ($sub.user) { $uname = [string]$sub.user.name; $utype = [string]$sub.user.type }
                $ctx.AzPrincipal = "$uname | sub=$($sub.name) ($($sub.id))"
                $ctx.AzAuthType  = switch ($utype) {
                    'user'            { 'Entra ID user (interactive / device code)' }
                    'servicePrincipal'{ 'Service principal' }
                    default           { if ($utype) { $utype } else { 'Unknown' } }
                }
                if ($sub.managedByTenants -and -not $ctx.AzAuthType) { $ctx.AzAuthType = 'Delegated (Lighthouse)' }
            }
        }
        if ($env:MSI_ENDPOINT -or $env:IDENTITY_ENDPOINT) {
            $ctx.AzAuthType = ($ctx.AzAuthType + ' + Managed Identity endpoint present').Trim(' +')
        }
    } catch { }

    return $ctx
}

function Get-PublicEgressIp {
    try {
        $r = Invoke-RestMethod -Uri 'https://checkip.amazonaws.com' -TimeoutSec 6 -ErrorAction Stop
        return ([string]$r).Trim()
    } catch {
        try {
            $r = Invoke-RestMethod -Uri 'https://ifconfig.me/ip' -TimeoutSec 6 -ErrorAction Stop
            return ([string]$r).Trim()
        } catch { return '' }
    }
}

# ============================================================================
#  COMMAND -> API / ATT&CK MAPPING
# ============================================================================

$script:AzProviderMap = @{
    'vm'='Microsoft.Compute'; 'vmss'='Microsoft.Compute'; 'disk'='Microsoft.Compute'; 'snapshot'='Microsoft.Compute'
    'image'='Microsoft.Compute'; 'storage'='Microsoft.Storage'; 'keyvault'='Microsoft.KeyVault'
    'network'='Microsoft.Network'; 'aks'='Microsoft.ContainerService'; 'acr'='Microsoft.ContainerRegistry'
    'webapp'='Microsoft.Web'; 'functionapp'='Microsoft.Web'; 'appservice'='Microsoft.Web'
    'sql'='Microsoft.Sql'; 'postgres'='Microsoft.DBforPostgreSQL'; 'mysql'='Microsoft.DBforMySQL'
    'cosmosdb'='Microsoft.DocumentDB'; 'monitor'='Microsoft.Insights'; 'group'='Microsoft.Resources'
    'resource'='Microsoft.Resources'; 'deployment'='Microsoft.Resources'; 'policy'='Microsoft.Authorization'
    'role'='Microsoft.Authorization'; 'lock'='Microsoft.Authorization'; 'identity'='Microsoft.ManagedIdentity'
    'ad'='Microsoft.Graph'; 'account'='Microsoft.Resources'; 'apim'='Microsoft.ApiManagement'
    'eventhubs'='Microsoft.EventHub'; 'servicebus'='Microsoft.ServiceBus'; 'appconfig'='Microsoft.AppConfiguration'
    'automation'='Microsoft.Automation'; 'backup'='Microsoft.RecoveryServices'; 'batch'='Microsoft.Batch'
    'containerapp'='Microsoft.App'; 'container'='Microsoft.ContainerInstance'; 'redis'='Microsoft.Cache'
    'search'='Microsoft.Search'; 'sig'='Microsoft.Compute'; 'synapse'='Microsoft.Synapse'
    'databricks'='Microsoft.Databricks'; 'logicapp'='Microsoft.Logic'; 'devops'='Azure DevOps'
    'security'='Microsoft.Security'; 'sentinel'='Microsoft.SecurityInsights'
}

function ConvertTo-PascalFromKebab {
    param([string]$Text)
    if (-not $Text) { return '' }
    return (($Text -split '-' | Where-Object { $_ } | ForEach-Object {
        $_.Substring(0,1).ToUpper() + $(if ($_.Length -gt 1) { $_.Substring(1) } else { '' })
    }) -join '')
}

function Split-CommandTokens {
    param([string]$Command)
    $tokens = @()
    $cur = New-Object System.Text.StringBuilder
    $inS = $false; $inD = $false
    foreach ($ch in $Command.ToCharArray()) {
        if ($ch -eq '"' -and -not $inS) { $inD = -not $inD; continue }
        if ($ch -eq "'" -and -not $inD) { $inS = -not $inS; continue }
        if (($ch -eq ' ' -or $ch -eq "`t") -and -not $inS -and -not $inD) {
            if ($cur.Length -gt 0) { $tokens += $cur.ToString(); [void]$cur.Clear() }
            continue
        }
        [void]$cur.Append($ch)
    }
    if ($cur.Length -gt 0) { $tokens += $cur.ToString() }
    return $tokens
}

function Resolve-AttackContext {
    param([string]$Cloud, [string]$Service, [string]$Operation, [string]$FullCommand)

    $op = $Operation.ToLower()
    $sv = $Service.ToLower()
    $fc = $FullCommand.ToLower()

    $rules = @(
        @{ M = 'delete-trail|stop-logging|put-event-selectors|delete-flow-logs|diagnostic-settings\s+delete|delete-log-group|deactivate-mfa|delete-alarm|update-trail|disable' ;
           T = 'TA0005 Defense Evasion / T1562.008 Disable or Modify Cloud Logs' ;
           I = 'Defence evasion - tamper with cloud logging/alerting' }
        @{ M = 'get-secret-value|secret\s+show|secret\s+list|get-parameter|get-parameters|decrypt|batch-get-secret|get-signing|show-connection-string|list-keys|keys\s+list|get-credential' ;
           T = 'TA0006 Credential Access / T1552.005 Cloud Instance Metadata & Secrets' ;
           I = 'Credential access - retrieve stored secrets/keys' }
        @{ M = 'assume-role|get-session-token|get-federation-token|attach-user-policy|attach-role-policy|attach-group-policy|put-user-policy|put-role-policy|create-access-key|update-assume-role-policy|role\s+assignment\s+create|add-member|update-policy-version|create-policy-version|set-iam-policy|add-iam-policy-binding' ;
           T = 'TA0004 Privilege Escalation / T1098.003 Additional Cloud Roles' ;
           I = 'Privilege escalation - modify or acquire elevated cloud permissions' }
        @{ M = 'create-user|create-login-profile|update-login-profile|create-service-linked-role|sp\s+create|app\s+create|credential\s+reset|user\s+create|create-role|add-user-to-group|import-key-pair' ;
           T = 'TA0003 Persistence / T1136.003 Create Cloud Account' ;
           I = 'Persistence - create or modify a cloud identity' }
        @{ M = 'run-instances|send-command|start-session|run-command|invoke|execute-command|start-build|create-job|start-pipeline-execution|update-function-code|create-function' ;
           T = 'TA0002 Execution / T1651 Cloud Administration Command' ;
           I = 'Execution - run code on cloud-managed compute' }
        @{ M = 'get-object|cp\s|sync\s|download|copy-snapshot|modify-snapshot-attribute|modify-image-attribute|create-db-snapshot|export|blob\s+download|share\s+create' ;
           T = 'TA0009 Collection / T1530 Data from Cloud Storage' ;
           I = 'Collection - read or copy data out of cloud storage' }
        @{ M = 'get-caller-identity|account\s+show|signed-in-user|whoami|get-user$|show-signed' ;
           T = 'TA0007 Discovery / T1078.004 Cloud Accounts (context check)' ;
           I = 'Discovery - confirm current cloud principal and account context' }
        @{ M = 'list-users|list-roles|list-groups|list-policies|list-attached|get-account-authorization-details|user\s+list|sp\s+list|group\s+list|role\s+assignment\s+list|role\s+definition\s+list|get-policy' ;
           T = 'TA0007 Discovery / T1087.004 Cloud Account Discovery' ;
           I = 'Discovery - enumerate identities, roles and policy bindings' }
        @{ M = 'describe-instances|describe-|list-|show$|get-|ls$|search|head-|account\s+list' ;
           T = 'TA0007 Discovery / T1580 Cloud Infrastructure Discovery' ;
           I = 'Discovery - enumerate cloud resources and configuration' }
    )

    foreach ($r in $rules) {
        if ($op -match $r.M -or $fc -match $r.M) {
            return @{ Attack = $r.T; Intent = $r.I }
        }
    }
    return @{ Attack = ''; Intent = '' }
}

function Resolve-CommandContext {
    param([string]$Command)

    $res = [ordered]@{
        Cloud = 'Local'; Service = ''; Operation = ''; Api = ''
        Attack = ''; Intent = ''; Region = ''; Endpoint = ''
    }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $res }

    $tokens = Split-CommandTokens $Command
    if ($tokens.Count -eq 0) { return $res }

    $exe = ($tokens[0] -replace '\.exe$', '').ToLower()
    $exe = ($exe -split '[\\/]')[-1]
    $rest = @()
    if ($tokens.Count -gt 1) { $rest = $tokens[1..($tokens.Count - 1)] }

    # Global flags that take a value and must not be mistaken for verbs.
    $valueFlags = @('--region','--profile','--output','--query','--endpoint-url','--cli-read-timeout',
                    '--cli-connect-timeout','--ca-bundle','--color','--subscription','-o','--only-show-errors',
                    '--cli-binary-format','--page-size','--max-items','--starting-token')

    switch ($exe) {

        'aws' {
            $res.Cloud = 'AWS'
            $positional = @()
            for ($i = 0; $i -lt $rest.Count; $i++) {
                $t = $rest[$i]
                if ($t -like '--region=*')     { $res.Region = $t.Split('=')[1]; continue }
                if ($t -eq '--region')         { $res.Region = $rest[$i+1]; $i++; continue }
                if ($t.StartsWith('-')) {
                    if ($valueFlags -contains $t -and $i + 1 -lt $rest.Count -and -not $rest[$i+1].StartsWith('-')) { $i++ }
                    continue
                }
                $positional += $t
                if ($positional.Count -ge 2) { break }
            }
            if ($positional.Count -ge 1) { $res.Service = $positional[0] }
            if ($positional.Count -ge 2) { $res.Operation = $positional[1] }

            if (-not $res.Region) {
                if ($env:AWS_REGION) { $res.Region = $env:AWS_REGION }
                elseif ($env:AWS_DEFAULT_REGION) { $res.Region = $env:AWS_DEFAULT_REGION }
            }

            if ($res.Service -eq 's3' -and $res.Operation -and $res.Operation -notmatch '-') {
                # high-level s3 verbs: ls / cp / mv / rm / sync / presign
                $res.Api = "s3:$($res.Operation) (high-level)"
            }
            elseif ($res.Service -and $res.Operation) {
                $res.Api = "$($res.Service):$(ConvertTo-PascalFromKebab $res.Operation)"
            }
            elseif ($res.Service) {
                $res.Api = "$($res.Service):<unspecified>"
            }

            $svcHost = if ($res.Service -eq 's3api') { 's3' } else { $res.Service }
            if ($svcHost) {
                $globalSvcs = @('iam','sts','s3','organizations','cloudfront','route53','waf','support','budgets')
                if ($globalSvcs -contains $svcHost -or -not $res.Region) { $res.Endpoint = "$svcHost.amazonaws.com" }
                else { $res.Endpoint = "$svcHost.$($res.Region).amazonaws.com" }
            }
        }

        'az' {
            $res.Cloud = 'Azure'
            $positional = @()
            for ($i = 0; $i -lt $rest.Count; $i++) {
                $t = $rest[$i]
                if ($t.StartsWith('-')) {
                    if ($valueFlags -contains $t -and $i + 1 -lt $rest.Count -and -not $rest[$i+1].StartsWith('-')) { $i++ }
                    continue
                }
                $positional += $t
            }
            if ($positional.Count -ge 1) {
                $group  = $positional[0]
                $path   = $positional -join ' '
                $res.Service   = $group
                $res.Operation = $path
                $prov = if ($script:AzProviderMap.ContainsKey($group.ToLower())) { $script:AzProviderMap[$group.ToLower()] } else { 'Microsoft.<unmapped>' }
                $res.Api = "az $path  [$prov]"
            }
            $res.Endpoint = if ($positional -and $positional[0] -eq 'ad') { 'graph.microsoft.com' } else { 'management.azure.com' }
        }

        'kubectl' {
            $res.Cloud = 'Kubernetes'
            if ($rest.Count -ge 1) { $res.Operation = ($rest | Where-Object { -not $_.StartsWith('-') }) -join ' ' }
            $res.Api = "k8s: $($res.Operation)"
        }

        default {
            if ($exe -match '^(get|set|new|remove|update|invoke|add|start|stop|restart|connect|disconnect|test|export|import|grant|revoke)-') {
                if ($exe -match '-az') { $res.Cloud = 'Azure'; $res.Api = "Az PowerShell: $($tokens[0])"; $res.Endpoint = 'management.azure.com' }
                elseif ($exe -match '-mg') { $res.Cloud = 'Azure'; $res.Api = "Microsoft Graph: $($tokens[0])"; $res.Endpoint = 'graph.microsoft.com' }
                elseif ($exe -match '-ec2|-s3|-iam|-sts') { $res.Cloud = 'AWS'; $res.Api = "AWS Tools for PowerShell: $($tokens[0])" }
                else { $res.Api = $tokens[0] }
                $res.Operation = $tokens[0]
            }
            elseif ($exe -in @('gcloud','gsutil','bq')) {
                $res.Cloud = 'GCP'
                $res.Operation = (($rest | Where-Object { -not $_.StartsWith('-') }) -join ' ')
                $res.Api = "gcloud: $($res.Operation)"
                $res.Endpoint = 'cloudresourcemanager.googleapis.com'
            }
            else {
                $res.Api = $exe
                $res.Operation = ($rest -join ' ')
            }
        }
    }

    $ac = Resolve-AttackContext -Cloud $res.Cloud -Service $res.Service -Operation $res.Operation -FullCommand $Command
    $res.Attack = $ac.Attack
    $res.Intent = $ac.Intent
    return $res
}

# ============================================================================
#  RESULT CLASSIFICATION
# ============================================================================

function Resolve-CommandResult {
    param(
        [string]$Output,
        [string]$Stderr = '',
        [int]$ExitCode,
        [string[]]$NewErrors,
        [bool]$PipelineOk
    )

    $reason = ''
    $isErr  = $false

    if ($ExitCode -ne 0) { $isErr = $true; $reason = "Non-zero exit code ($ExitCode)" }
    if (-not $PipelineOk -and -not $isErr) { $isErr = $true; $reason = 'PowerShell reported command failure' }

    $patterns = @(
        @{ Rx = 'An error occurred \(([^)]+)\) when calling the (\S+) operation:?\s*(.*)' ; Fmt = { param($m) "AWS $($m.Groups[1].Value) on $($m.Groups[2].Value): $($m.Groups[3].Value)" } }
        @{ Rx = '(?m)^ERROR:\s*(.+)$'                                                    ; Fmt = { param($m) "Azure CLI error: $($m.Groups[1].Value)" } }
        @{ Rx = '"Code"\s*:\s*"([^"]+)"[^}]*"Message"\s*:\s*"([^"]+)"'                   ; Fmt = { param($m) "$($m.Groups[1].Value): $($m.Groups[2].Value)" } }
        @{ Rx = '\(([A-Za-z]*(?:AuthorizationFailed|Forbidden|Unauthorized|AccessDenied|InvalidAuthenticationToken|ExpiredToken)[A-Za-z]*)\)\s*(.*)' ; Fmt = { param($m) "$($m.Groups[1].Value): $($m.Groups[2].Value)" } }
        @{ Rx = '(?m)^(Unable to locate credentials|The security token included in the request is (?:expired|invalid))' ; Fmt = { param($m) "Credential problem: $($m.Groups[1].Value)" } }
        @{ Rx = '(?m)^(Please run .az login. to setup account|AADSTS\d+:.*)$'            ; Fmt = { param($m) "Entra/Azure auth: $($m.Groups[1].Value)" } }
        @{ Rx = '(?m)^(usage: aws .+|az: error: .+|.+: error: unrecognized arguments.+)$'; Fmt = { param($m) "CLI usage error: $($m.Groups[1].Value)" } }
    )

    # A signature found in STDERR can flag a failure. The same signature in
    # STDOUT may only enrich the reason for an already-failed command - stdout
    # legitimately contains words like ERROR when you are reading someone else's
    # logs, and `aws logs tail` should not be scored as a failed command.
    $sources = @($Stderr)
    if ($isErr) { $sources += $Output }
    $matched = $false
    foreach ($src in $sources) {
        if ($matched -or [string]::IsNullOrWhiteSpace($src)) { continue }
        foreach ($p in $patterns) {
            $m = [regex]::Match($src, $p.Rx)
            if ($m.Success) {
                $isErr   = $true
                $reason  = (& $p.Fmt $m)
                $matched = $true
                break
            }
        }
    }

    if (-not $reason -and $NewErrors -and $NewErrors.Count -gt 0) {
        $isErr = $true
        $reason = "PowerShell exception: $($NewErrors[0])"
    }

    if (-not $isErr) {
        $reason = "Exit code 0"
        $trimmed = $Output.Trim()
        if ($trimmed.StartsWith('[') -or $trimmed.StartsWith('{')) {
            $n = ([regex]::Matches($trimmed, '(?m)^\s{0,8}\{')).Count
            if ($n -gt 0) { $reason = "Exit code 0 - JSON response (~$n object(s))" }
        }
        elseif (-not $trimmed) { $reason = 'Exit code 0 - no output' }
        else {
            $lines = ($trimmed -split "`n").Count
            $reason = "Exit code 0 - $lines line(s) of output"
        }
    }

    if ($reason.Length -gt 500) { $reason = $reason.Substring(0, 497) + '...' }

    return @{ Result = $(if ($isErr) { 'Error' } else { 'Success' }); Reason = $reason.Trim() }
}

# ============================================================================
#  NETWORK CONNECTION SAMPLER
# ============================================================================

$script:Sampler = $null

function Get-TcpSnapshotFallback {
    # netstat parser for hosts without the NetTCPIP module.
    $rows = @()
    try {
        $out = & netstat -ano -p TCP 2>$null
        foreach ($line in $out) {
            if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') {
                $rows += [pscustomobject]@{
                    LocalAddress  = $Matches[1]; LocalPort  = [int]$Matches[2]
                    RemoteAddress = $Matches[3]; RemotePort = [int]$Matches[4]
                    State         = $Matches[5]; OwningProcess = [int]$Matches[6]
                }
            }
        }
    } catch { }
    return $rows
}

function Start-ConnectionSampler {
    $sync = [hashtable]::Synchronized(@{
        Stop     = $false
        Items    = (New-Object System.Collections.ArrayList)
        Baseline = (New-Object System.Collections.Generic.HashSet[string])
        UseCmdlet = $true
    })

    $sync.UseCmdlet = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)

    # Baseline: connections already present before the command runs.
    try {
        $snap = if ($sync.UseCmdlet) { Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue }
                else { Get-TcpSnapshotFallback | Where-Object { $_.State -eq 'ESTABLISHED' } }
        foreach ($c in $snap) {
            [void]$sync.Baseline.Add("$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)")
        }
    } catch { }

    $sb = {
        param($sync)
        $pidNames = @{}
        while (-not $sync.Stop) {
            try {
                $snap = if ($sync.UseCmdlet) { Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue }
                        else {
                            $rows = @()
                            $out = & netstat -ano -p TCP 2>$null
                            foreach ($line in $out) {
                                if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+ESTABLISHED\s+(\d+)\s*$') {
                                    $rows += [pscustomobject]@{
                                        LocalAddress=$Matches[1]; LocalPort=[int]$Matches[2]
                                        RemoteAddress=$Matches[3]; RemotePort=[int]$Matches[4]
                                        OwningProcess=[int]$Matches[5]
                                    }
                                }
                            }
                            $rows
                        }
                foreach ($c in $snap) {
                    $key = "$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)"
                    if ($sync.Baseline.Contains($key)) { continue }
                    [void]$sync.Baseline.Add($key)
                    $ownPid = [int]$c.OwningProcess
                    if (-not $pidNames.ContainsKey($ownPid)) {
                        $n = ''
                        try { $n = (Get-Process -Id $ownPid -ErrorAction Stop).ProcessName } catch { $n = '' }
                        $pidNames[$ownPid] = $n
                    }
                    [void]$sync.Items.Add([pscustomobject]@{
                        LocalAddress  = [string]$c.LocalAddress
                        LocalPort     = [int]$c.LocalPort
                        RemoteAddress = [string]$c.RemoteAddress
                        RemotePort    = [int]$c.RemotePort
                        ProcId        = $ownPid
                        ProcName      = $pidNames[$ownPid]
                    })
                }
            } catch { }
            Start-Sleep -Milliseconds 120
        }
    }

    try {
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'MTA'
        $rs.ThreadOptions  = 'ReuseThread'
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript($sb).AddArgument($sync)
        $handle = $ps.BeginInvoke()
        $script:Sampler = @{ Sync = $sync; PS = $ps; RS = $rs; Handle = $handle }
    } catch {
        $script:Sampler = @{ Sync = $sync; PS = $null; RS = $null; Handle = $null }
    }
}

function Stop-ConnectionSampler {
    param([string]$PreferredEndpoint = '')

    $result = [ordered]@{ SrcIP = ''; SrcPort = ''; DstIP = ''; DstPort = ''; Note = '' }
    if (-not $script:Sampler) { return $result }

    $script:Sampler.Sync.Stop = $true
    Start-Sleep -Milliseconds 180
    try {
        if ($script:Sampler.PS) {
            [void]$script:Sampler.PS.EndInvoke($script:Sampler.Handle)
            $script:Sampler.PS.Dispose()
        }
        if ($script:Sampler.RS) { $script:Sampler.RS.Close(); $script:Sampler.RS.Dispose() }
    } catch { }

    $items = @($script:Sampler.Sync.Items)
    $script:Sampler = $null

    $interesting = @('aws','az','python','python3','pwsh','powershell','cmd','curl','node','dotnet','kubectl','gcloud','msiexec')
    $cands = $items | Where-Object {
        -not (Test-PrivateIp $_.RemoteAddress) -and ($_.RemotePort -in @(443, 80, 8443))
    }

    $pick = $cands | Where-Object { $interesting -contains ([string]$_.ProcName).ToLower() } | Select-Object -First 1
    if (-not $pick) { $pick = $cands | Select-Object -First 1 }

    if ($pick) {
        $result.SrcIP   = $pick.LocalAddress
        $result.SrcPort = [string]$pick.LocalPort
        $result.DstIP   = $pick.RemoteAddress
        $result.DstPort = [string]$pick.RemotePort
        if ($cands.Count -gt 1) { $result.Note = "$($cands.Count) new egress connections observed; first/best shown" }
        return $result
    }

    # Fallback: resolve the expected service endpoint and derive the local route.
    if ($PreferredEndpoint) {
        try {
            $ip = ([System.Net.Dns]::GetHostAddresses($PreferredEndpoint) |
                   Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
            if ($ip) {
                $result.DstIP   = $ip
                $result.DstPort = '443'
                $result.Note    = "Destination resolved from endpoint $PreferredEndpoint (connection not sampled)"
                try {
                    $route = Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop | Select-Object -First 1
                    if ($route) { $result.SrcIP = $route.IPAddress }
                } catch { }
            }
        } catch { }
    }
    return $result
}

# ============================================================================
#  SESSION STORAGE (JSONL journal + meta)
# ============================================================================

function Initialize-DataRoot {
    if (-not (Test-Path $script:DataRoot)) {
        [void](New-Item -ItemType Directory -Path $script:DataRoot -Force)
    }
}

# ---------------------------------------------------------------------------
#  Layout: one directory per session.
#
#    <DataRoot>\<yyyy-MM-dd HH-mm-ss> - <Name>\
#        session.meta.json
#        session.jsonl
#        <yyyy-MM-dd HH-mm-ss> - <Name>.xlsx
#        outputs\
#
#  Everywhere below, $Base is that DIRECTORY, not a filename prefix.
# ---------------------------------------------------------------------------

function Get-MetaPath    { param([string]$Base) Join-Path $Base 'session.meta.json' }
function Get-JournalPath { param([string]$Base) Join-Path $Base 'session.jsonl' }
function Get-OutputsPath { param([string]$Base) Join-Path $Base 'outputs' }
function Get-XlsxPath    { param([string]$Base) Join-Path $Base ((Split-Path $Base -Leaf) + '.xlsx') }

function Convert-LegacyLayout {
    # v1.0.x wrote sessions as flat sibling files. Fold any it finds into folders.
    $legacy = Get-ChildItem -Path $script:DataRoot -Filter '*.meta.json' -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -ne 'session.meta.json' }
    foreach ($m in $legacy) {
        try {
            $stem = $m.Name -replace '\.meta\.json$', ''
            $dir  = Join-Path $script:DataRoot $stem
            if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }

            Move-Item -LiteralPath $m.FullName -Destination (Get-MetaPath $dir) -Force -ErrorAction SilentlyContinue

            $oldJournal = Join-Path $script:DataRoot "$stem.jsonl"
            if (Test-Path -LiteralPath $oldJournal) {
                Move-Item -LiteralPath $oldJournal -Destination (Get-JournalPath $dir) -Force -ErrorAction SilentlyContinue
            }
            $oldXlsx = Join-Path $script:DataRoot "$stem.xlsx"
            if (Test-Path -LiteralPath $oldXlsx) {
                Move-Item -LiteralPath $oldXlsx -Destination (Get-XlsxPath $dir) -Force -ErrorAction SilentlyContinue
            }
            $oldOut = Join-Path $script:DataRoot "$stem.outputs"
            if (Test-Path -LiteralPath $oldOut) {
                $newOut = Get-OutputsPath $dir
                if (-not (Test-Path $newOut)) { Move-Item -LiteralPath $oldOut -Destination $newOut -Force -ErrorAction SilentlyContinue }
            }
            # Excel lock/temp leftovers are not evidence; drop them.
            foreach ($junk in @("$stem.xlsx.tmp", "$stem.jsonl.tmp", "~`$$stem.xlsx")) {
                $jp = Join-Path $script:DataRoot $junk
                if (Test-Path -LiteralPath $jp) { Remove-Item -LiteralPath $jp -Force -ErrorAction SilentlyContinue }
            }
            if (-not (Test-Path (Get-OutputsPath $dir))) { [void](New-Item -ItemType Directory -Path (Get-OutputsPath $dir) -Force) }
        } catch { }
    }
}

function Get-SessionList {
    Initialize-DataRoot
    # Migration must never be able to take discovery down with it.
    try { Convert-LegacyLayout } catch { }

    $list = @()
    $script:LastRejected = @()

    $dirs = @(Get-ChildItem -LiteralPath $script:DataRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($d in $dirs) {
        $metaPath = Get-MetaPath $d.FullName
        $jrnPath  = Get-JournalPath $d.FullName
        $hasMeta  = Test-Path -LiteralPath $metaPath
        $hasJrn   = Test-Path -LiteralPath $jrnPath
        $hasXlsx  = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.xlsx' -File -ErrorAction SilentlyContinue).Count -gt 0

        if (-not ($hasMeta -or $hasJrn -or $hasXlsx)) {
            $script:LastRejected += "$($d.Name)  ->  no session.meta.json, session.jsonl or .xlsx inside"
            continue
        }

        $j = $null
        if ($hasMeta) {
            try {
                $rawMeta = Get-Content -LiteralPath $metaPath -Raw -ErrorAction Stop
                if ($rawMeta) { $rawMeta = $rawMeta -replace '^\uFEFF', '' }
                $j = $rawMeta | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $script:LastRejected += "$($d.Name)  ->  session.meta.json unreadable: $($_.Exception.Message)"
                $j = $null
            }
        }

        if (-not $j) {
            # A damaged or missing meta file must not cost you the session. Rebuild
            # the minimum from the folder name and the journal, then persist it.
            $nm = $d.Name
            if ($nm -match '^\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2} - (.+)$') { $nm = $Matches[1] }
            $j = [pscustomobject]@{
                SchemaVersion = $script:SchemaVer
                Tool          = "$($script:AppName) $($script:AppVersion)"
                Name          = $nm
                CreatedLocal  = ''
                CreatedUtc    = ''
                Machine       = $env:COMPUTERNAME
                OsUser        = "$env:USERDOMAIN\$env:USERNAME"
                LogonType     = 'Unknown'
                AwsPrincipal  = ''
                AwsAuthType   = ''
                AzPrincipal   = ''
                AzAuthType    = ''
                PublicEgressIp= ''
                NextRowId     = 1
            }
            if ($hasJrn) {
                $maxId = 0
                foreach ($ln in (Get-Content -LiteralPath $jrnPath -ErrorAction SilentlyContinue)) {
                    if ($ln -match '"RowId"\s*:\s*(\d+)') {
                        $v = [int]$Matches[1]
                        if ($v -gt $maxId) { $maxId = $v }
                    }
                }
                $j.NextRowId = $maxId + 1
            }
            try { Save-SessionMeta -Base $d.FullName -Meta $j } catch { }
        }

        $count = 0
        if ($hasJrn) {
            $count = @(Get-Content -LiteralPath $jrnPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() }).Count
        }

        $list += [pscustomobject]@{
            Base      = $d.FullName
            BaseName  = $d.Name
            Name      = $(if ($j.Name) { $j.Name } else { $d.Name })
            Created   = $j.CreatedLocal
            Machine   = $j.Machine
            User      = $j.OsUser
            Records   = $count
            Meta      = $j
        }
    }
    # Comma prevents PowerShell unrolling an empty/single-item array on return,
    # which made $sessions.Count come back blank instead of 0 or 1.
    return ,$list
}

function Show-SkippedFolders {
    if ($script:LastRejected -and $script:LastRejected.Count -gt 0) {
        Write-T ''
        Write-T '  Folders skipped during discovery:' 'Warn'
        foreach ($r in $script:LastRejected) { Write-T "    $r" 'Warn' }
    }
}

function New-SessionFiles {
    param([string]$Name)
    Initialize-DataRoot
    $now  = Get-Date
    $safe = Get-SafeFileName $Name
    $base = Join-Path $script:DataRoot ("{0} - {1}" -f $now.ToString('yyyy-MM-dd HH-mm-ss'), $safe)
    if (-not (Test-Path $base)) { [void](New-Item -ItemType Directory -Path $base -Force) }

    $auth = Get-CloudAuthContext
    $meta = [ordered]@{
        SchemaVersion = $script:SchemaVer
        Tool          = "$($script:AppName) $($script:AppVersion)"
        Name          = $Name
        CreatedLocal  = Format-Stamp $now
        CreatedUtc    = Format-Stamp $now.ToUniversalTime()
        Machine       = $env:COMPUTERNAME
        OsUser        = "$env:USERDOMAIN\$env:USERNAME"
        LogonType     = (Get-WindowsLogonType)
        AwsPrincipal  = $auth.AwsPrincipal
        AwsAuthType   = $auth.AwsAuthType
        AzPrincipal   = $auth.AzPrincipal
        AzAuthType    = $auth.AzAuthType
        PublicEgressIp= ''
        NextRowId     = 1
    }
    $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Get-MetaPath $base) -Encoding UTF8
    [void](New-Item -ItemType File -Path (Get-JournalPath $base) -Force)
    [void](New-Item -ItemType Directory -Path (Get-OutputsPath $base) -Force)
    return $base
}

function Get-SessionMeta {
    param([string]$Base)
    $m = $null
    try {
        $raw = Get-Content -LiteralPath (Get-MetaPath $Base) -Raw -Encoding UTF8 -ErrorAction Stop
        if ($raw) { $raw = $raw -replace '^\uFEFF', '' }
        if ($raw -and $raw.Trim()) { $m = $raw | ConvertFrom-Json -ErrorAction Stop }
    } catch { $m = $null }
    # An empty or unreadable meta file yields $null; start from a bare object so
    # the schema backfill below has something to attach properties to.
    if ($null -eq $m) { $m = [pscustomobject]@{} }
    # Meta files written by older versions may be missing fields added later.
    # ConvertFrom-Json yields a PSCustomObject, and assigning a property that is
    # absent throws PropertyNotFound - so backfill the full schema with defaults.
    $defaults = [ordered]@{
        SchemaVersion  = $script:SchemaVer
        Tool           = "$($script:AppName) $($script:AppVersion)"
        Name           = Split-Path $Base -Leaf
        CreatedLocal   = ''
        CreatedUtc     = ''
        Machine        = $env:COMPUTERNAME
        OsUser         = "$env:USERDOMAIN\$env:USERNAME"
        LogonType      = 'Unknown'
        AwsPrincipal   = ''
        AwsAuthType    = ''
        AzPrincipal    = ''
        AzAuthType     = ''
        PublicEgressIp = ''
        NextRowId      = 1
    }
    foreach ($k in $defaults.Keys) {
        if ($m.PSObject.Properties.Name -notcontains $k) {
            Add-Member -InputObject $m -MemberType NoteProperty -Name $k -Value $defaults[$k] -Force
        }
    }
    return $m
}

function Save-SessionMeta {
    param([string]$Base, $Meta)
    $Meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Get-MetaPath $Base) -Encoding UTF8
}

function Get-JournalRecords {
    param([string]$Base)
    $recs = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath (Get-JournalPath $Base))) { return ,$recs }
    foreach ($line in [IO.File]::ReadAllLines((Get-JournalPath $Base))) {
        if (-not $line.Trim()) { continue }
        try { [void]$recs.Add(($line | ConvertFrom-Json)) } catch { }
    }
    # Leading comma stops PowerShell unrolling the list on return. Without it a
    # one-record session came back as a bare object and $records.Count was blank.
    return ,$recs
}

function Add-JournalRecord {
    param([string]$Base, $Record)
    $json = ($Record | ConvertTo-Json -Depth 6 -Compress)
    Add-Content -LiteralPath (Get-JournalPath $Base) -Value $json -Encoding UTF8
}

function Save-JournalRecords {
    param([string]$Base, $Records)
    $tmp = (Get-JournalPath $Base) + '.tmp'
    $sw = New-Object System.IO.StreamWriter($tmp, $false, (New-Object System.Text.UTF8Encoding($false)))
    try {
        foreach ($r in $Records) { $sw.WriteLine(($r | ConvertTo-Json -Depth 6 -Compress)) }
    } finally { $sw.Dispose() }
    [System.IO.File]::Copy($tmp, (Get-JournalPath $Base), $true)
    [System.IO.File]::Delete($tmp)
}

function New-EmptyRecord {
    $r = [ordered]@{}
    foreach ($k in $script:Schema.Keys) { $r[$k] = '' }
    return $r
}

# ============================================================================
#  XLSX WRITER  (zero dependency, OOXML)
# ============================================================================

function Get-ColumnLetter {
    param([int]$Index)   # 1-based
    $s = ''
    $n = $Index
    while ($n -gt 0) {
        $rem = ($n - 1) % 26
        $s = [char](65 + $rem) + $s
        $n = [int](($n - $rem - 1) / 26)
    }
    return $s
}

function Add-ZipTextEntry {
    param($Archive, [string]$EntryName, [string]$Content)
    $entry = $Archive.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
    $writer.Write($Content)
    $writer.Flush(); $writer.Dispose(); $stream.Dispose()
}

function Get-StylesXml {
@'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="4">
    <font><sz val="10"/><color rgb="FF1B1B1B"/><name val="Consolas"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Segoe UI Semibold"/></font>
    <font><sz val="10"/><color rgb="FF8A0000"/><name val="Consolas"/></font>
    <font><b/><sz val="10"/><color rgb="FF3B0066"/><name val="Consolas"/></font>
  </fonts>
  <fills count="5">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFA100FF"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFFE2E2"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF3E8FF"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFD9C2F0"/></left>
      <right style="thin"><color rgb="FFD9C2F0"/></right>
      <top style="thin"><color rgb="FFD9C2F0"/></top>
      <bottom style="thin"><color rgb="FFD9C2F0"/></bottom>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="5">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">
      <alignment horizontal="center" vertical="center" wrapText="1"/>
    </xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1">
      <alignment vertical="top" wrapText="1"/>
    </xf>
    <xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">
      <alignment vertical="top" wrapText="1"/>
    </xf>
    <xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">
      <alignment vertical="top" wrapText="1"/>
    </xf>
  </cellXfs>
</styleSheet>
'@
}

function Export-SessionWorkbook {
    param([string]$Base, [switch]$Quiet)

    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $records = Get-JournalRecords -Base $Base
    $meta    = Get-SessionMeta -Base $Base
    $headers = @($script:Schema.Values)
    $fields  = @($script:Schema.Keys)
    $nCols   = $headers.Count
    $lastCol = Get-ColumnLetter $nCols

    # ---------- sheet1: Session ----------
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$sb.Append('<sheetPr><outlinePr summaryBelow="1" summaryRight="1"/></sheetPr>')
    [void]$sb.Append("<dimension ref=""A1:$lastCol$([Math]::Max(1, $records.Count + 1))""/>")
    [void]$sb.Append('<sheetViews><sheetView tabSelected="1" workbookViewId="0">')
    [void]$sb.Append('<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>')
    [void]$sb.Append('</sheetView></sheetViews>')
    [void]$sb.Append('<sheetFormatPr defaultRowHeight="15"/>')

    [void]$sb.Append('<cols>')
    for ($i = 1; $i -le $nCols; $i++) {
        $w = if ($i - 1 -lt $script:ColWidths.Count) { $script:ColWidths[$i - 1] } else { 20 }
        [void]$sb.Append("<col min=""$i"" max=""$i"" width=""$w"" customWidth=""1""/>")
    }
    [void]$sb.Append('</cols>')

    [void]$sb.Append('<sheetData>')
    # header row
    [void]$sb.Append('<row r="1" ht="30" customHeight="1">')
    for ($i = 0; $i -lt $nCols; $i++) {
        $ref = (Get-ColumnLetter ($i + 1)) + '1'
        [void]$sb.Append("<c r=""$ref"" s=""1"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $headers[$i])</t></is></c>")
    }
    [void]$sb.Append('</row>')

    $rowNum = 1
    foreach ($rec in $records) {
        $rowNum++
        $isErr = ([string]$rec.Result -eq 'Error')
        [void]$sb.Append("<row r=""$rowNum"">")
        for ($i = 0; $i -lt $nCols; $i++) {
            $field = $fields[$i]
            $val   = ''
            if ($rec.PSObject.Properties.Name -contains $field) { $val = [string]$rec.$field }
            if ($val.Length -gt $script:MaxCellChars) {
                $val = $val.Substring(0, $script:MaxCellChars) + "`r`n...[TRUNCATED - see Output File column]"
            }
            $style = if ($field -eq 'RowId') { 4 } elseif ($isErr) { 3 } else { 2 }
            $ref = (Get-ColumnLetter ($i + 1)) + $rowNum
            if ($val -eq '') {
                [void]$sb.Append("<c r=""$ref"" s=""$style""/>")
            } else {
                [void]$sb.Append("<c r=""$ref"" s=""$style"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $val)</t></is></c>")
            }
        }
        [void]$sb.Append('</row>')
    }
    [void]$sb.Append('</sheetData>')
    if ($records.Count -gt 0) {
        [void]$sb.Append("<autoFilter ref=""A1:$lastCol$rowNum""/>")
    }
    [void]$sb.Append('</worksheet>')
    $sheet1 = $sb.ToString()

    # ---------- sheet2: Session Info ----------
    $infoPairs = @()
    foreach ($p in $meta.PSObject.Properties) { $infoPairs += ,@($p.Name, [string]$p.Value) }
    $infoPairs += ,@('RecordCount', [string]$records.Count)
    $infoPairs += ,@('WorkbookRenderedLocal', (Format-Stamp (Get-Date)))
    $infoPairs += ,@('WorkbookRenderedUtc', (Format-Stamp ((Get-Date).ToUniversalTime())))

    $sb2 = New-Object System.Text.StringBuilder
    [void]$sb2.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb2.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$sb2.Append('<cols><col min="1" max="1" width="26" customWidth="1"/><col min="2" max="2" width="90" customWidth="1"/></cols>')
    [void]$sb2.Append('<sheetData>')
    [void]$sb2.Append('<row r="1"><c r="A1" s="1" t="inlineStr"><is><t>Property</t></is></c><c r="B1" s="1" t="inlineStr"><is><t>Value</t></is></c></row>')
    $r = 1
    foreach ($pair in $infoPairs) {
        $r++
        [void]$sb2.Append("<row r=""$r"">")
        [void]$sb2.Append("<c r=""A$r"" s=""4"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $pair[0])</t></is></c>")
        [void]$sb2.Append("<c r=""B$r"" s=""2"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $pair[1])</t></is></c>")
        [void]$sb2.Append('</row>')
    }
    [void]$sb2.Append('</sheetData></worksheet>')
    $sheet2 = $sb2.ToString()

    # ---------- sheet3: Variables ----------
    # Sourced from variables.json rather than the in-memory table, so the Edit
    # menu can re-render a session that is not the one currently open.
    $varRecs = @(Get-SessionVariableRecords -Base $Base)
    $varHeaders = @('Name','Type','Length','Value','Changes','First Set','Last Set','Set At Row','Sensitive','Restorable','Set By Command')
    $varFields  = @('Name','Type','Length','Value','Changes','FirstSet','LastSet','SetAtRow','Sensitive','Restorable','SetBy')
    $varWidths  = @(24, 14, 9, 60, 9, 19, 19, 11, 11, 11, 70)

    $sb3 = New-Object System.Text.StringBuilder
    [void]$sb3.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb3.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$sb3.Append('<sheetViews><sheetView workbookViewId="0">')
    [void]$sb3.Append('<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>')
    [void]$sb3.Append('</sheetView></sheetViews>')
    [void]$sb3.Append('<cols>')
    for ($i = 1; $i -le $varHeaders.Count; $i++) {
        $w = $varWidths[$i - 1]
        [void]$sb3.Append("<col min=""$i"" max=""$i"" width=""$w"" customWidth=""1""/>")
    }
    [void]$sb3.Append('</cols><sheetData>')
    [void]$sb3.Append('<row r="1" ht="26" customHeight="1">')
    for ($i = 0; $i -lt $varHeaders.Count; $i++) {
        $ref = (Get-ColumnLetter ($i + 1)) + '1'
        [void]$sb3.Append("<c r=""$ref"" s=""1"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $varHeaders[$i])</t></is></c>")
    }
    [void]$sb3.Append('</row>')
    $vRow = 1
    foreach ($vr in $varRecs) {
        $vRow++
        [void]$sb3.Append("<row r=""$vRow"">")
        for ($i = 0; $i -lt $varFields.Count; $i++) {
            $f = $varFields[$i]
            $val = ''
            if ($vr.PSObject.Properties.Name -contains $f) { $val = [string]$vr.$f }
            if ($f -eq 'Name' -and $val) { $val = '$' + $val }
            if ($val.Length -gt $script:MaxCellChars) { $val = $val.Substring(0, $script:MaxCellChars) + '...' }
            $st = if ($i -eq 0) { 4 } else { 2 }
            $ref = (Get-ColumnLetter ($i + 1)) + $vRow
            if ($val -eq '') { [void]$sb3.Append("<c r=""$ref"" s=""$st""/>") }
            else { [void]$sb3.Append("<c r=""$ref"" s=""$st"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $val)</t></is></c>") }
        }
        [void]$sb3.Append('</row>')
    }
    [void]$sb3.Append('</sheetData>')
    if ($varRecs.Count -gt 0) {
        [void]$sb3.Append("<autoFilter ref=""A1:$(Get-ColumnLetter $varHeaders.Count)$vRow""/>")
    }
    [void]$sb3.Append('</worksheet>')
    $sheet3 = $sb3.ToString()

    $contentTypes = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
'@

    $rootRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
'@

    $workbook = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Session" sheetId="1" r:id="rId1"/>
    <sheet name="Variables" sheetId="2" r:id="rId2"/>
    <sheet name="Session Info" sheetId="3" r:id="rId3"/>
  </sheets>
</workbook>
'@

    $wbRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
'@

    $nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $core = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>$(ConvertTo-XmlText $meta.Name) - $(ConvertTo-XmlText $script:AppName) session</dc:title>
  <dc:creator>$(ConvertTo-XmlText $meta.OsUser)</dc:creator>
  <cp:lastModifiedBy>$(ConvertTo-XmlText $script:AppName)</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">$nowIso</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">$nowIso</dcterms:modified>
</cp:coreProperties>
"@

    $app = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>$(ConvertTo-XmlText "$($script:AppName) $($script:AppVersion)")</Application>
</Properties>
"@

    $target = Get-XlsxPath $Base
    $tmp    = (Get-XlsxPath $Base) + '.tmp'
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

    $fs = $null; $zip = $null
    try {
        $fs  = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $true)

        Add-ZipTextEntry $zip '[Content_Types].xml'        $contentTypes
        Add-ZipTextEntry $zip '_rels/.rels'                $rootRels
        Add-ZipTextEntry $zip 'docProps/core.xml'          $core
        Add-ZipTextEntry $zip 'docProps/app.xml'           $app
        Add-ZipTextEntry $zip 'xl/workbook.xml'            $workbook
        Add-ZipTextEntry $zip 'xl/_rels/workbook.xml.rels' $wbRels
        Add-ZipTextEntry $zip 'xl/styles.xml'              (Get-StylesXml)
        Add-ZipTextEntry $zip 'xl/worksheets/sheet1.xml'   $sheet1
        Add-ZipTextEntry $zip 'xl/worksheets/sheet2.xml'   $sheet2
        Add-ZipTextEntry $zip 'xl/worksheets/sheet3.xml'   $sheet3
    }
    finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    try {
        # Move-Item -Force does not reliably replace an existing file and reports
        # failure as a NON-terminating error, so the old code claimed success.
        [System.IO.File]::Copy($tmp, $target, $true)
        [System.IO.File]::Delete($tmp)
        if (-not $Quiet) { Write-T "  [xlsx] $target  ($($records.Count) record(s))" 'Ok' }
        return $true
    } catch {
        if (-not $Quiet) {
            Write-T "  [xlsx] Could not replace $target - is it open in Excel?" 'Err'
            Write-T "         Rendered copy left at: $tmp" 'Warn'
        }
        return $false
    }
}

# ============================================================================
#  XLSX READER  (pull operator edits made directly in Excel back into journal)
# ============================================================================

function Import-SessionWorkbook {
    param([string]$Base)

    $path = Get-XlsxPath $Base
    if (-not (Test-Path $path)) { Write-T '  No workbook to import.' 'Err'; return $false }

    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $sheetXml = $null; $sharedXml = $null
    $fs = $null; $zip = $null
    try {
        $fs  = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
        foreach ($e in $zip.Entries) {
            if ($e.FullName -eq 'xl/worksheets/sheet1.xml') {
                $sr = New-Object System.IO.StreamReader($e.Open()); $sheetXml = $sr.ReadToEnd(); $sr.Dispose()
            }
            elseif ($e.FullName -eq 'xl/sharedStrings.xml') {
                $sr = New-Object System.IO.StreamReader($e.Open()); $sharedXml = $sr.ReadToEnd(); $sr.Dispose()
            }
        }
    } catch {
        Write-T "  Failed to open workbook: $($_.Exception.Message)" 'Err'
        return $false
    } finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    if (-not $sheetXml) { Write-T '  Worksheet part not found.' 'Err'; return $false }

    # shared strings
    $shared = @()
    if ($sharedXml) {
        try {
            [xml]$sx = $sharedXml
            foreach ($si in $sx.sst.si) {
                if ($si.t -is [string]) { $shared += [string]$si.t }
                elseif ($si.t) { $shared += [string]$si.t.'#text' }
                elseif ($si.r) { $shared += (($si.r | ForEach-Object { if ($_.t -is [string]) { $_.t } else { $_.t.'#text' } }) -join '') }
                else { $shared += '' }
            }
        } catch { }
    }

    try { [xml]$doc = $sheetXml } catch { Write-T '  Worksheet XML is malformed.' 'Err'; return $false }

    $grid = @{}
    foreach ($row in $doc.worksheet.sheetData.row) {
        $rn = [int]$row.r
        foreach ($c in $row.c) {
            if (-not $c.r) { continue }
            $col = ($c.r -replace '\d', '')
            $t = [string]$c.t
            $val = ''
            if ($t -eq 's') {
                $idx = [int]$c.v
                if ($idx -ge 0 -and $idx -lt $shared.Count) { $val = $shared[$idx] }
            }
            elseif ($t -eq 'inlineStr') {
                if ($c.is.t -is [string]) { $val = [string]$c.is.t }
                elseif ($c.is.t) { $val = [string]$c.is.t.'#text' }
            }
            elseif ($t -eq 'str') { $val = [string]$c.v }
            else { $val = [string]$c.v }
            if (-not $grid.ContainsKey($rn)) { $grid[$rn] = @{} }
            $grid[$rn][$col] = $val
        }
    }

    if (-not $grid.ContainsKey(1)) { Write-T '  No header row found.' 'Err'; return $false }

    # header -> field
    $hdrToField = @{}
    foreach ($k in $script:Schema.Keys) { $hdrToField[[string]$script:Schema[$k]] = $k }
    $colToField = @{}
    foreach ($col in $grid[1].Keys) {
        $h = $grid[1][$col]
        if ($hdrToField.ContainsKey($h)) { $colToField[$col] = $hdrToField[$h] }
    }
    if ($colToField.Count -eq 0) { Write-T '  Header names do not match the schema; aborting import.' 'Err'; return $false }

    $existing = Get-JournalRecords -Base $Base
    $byId = @{}
    foreach ($r in $existing) { $byId[[string]$r.RowId] = $r }

    $newList = New-Object System.Collections.Generic.List[object]
    $changed = 0
    $rowNums = $grid.Keys | Where-Object { $_ -gt 1 } | Sort-Object
    foreach ($rn in $rowNums) {
        $cells = $grid[$rn]
        $rec = $null
        $rowIdCol = ($colToField.GetEnumerator() | Where-Object { $_.Value -eq 'RowId' } | Select-Object -First 1)
        $rowId = if ($rowIdCol) { [string]$cells[$rowIdCol.Key] } else { '' }
        if ($rowId -and $byId.ContainsKey($rowId)) { $rec = $byId[$rowId] }
        else {
            $rec = New-Object PSObject
            foreach ($k in $script:Schema.Keys) { Add-Member -InputObject $rec -MemberType NoteProperty -Name $k -Value '' -Force }
        }
        foreach ($col in $cells.Keys) {
            if (-not $colToField.ContainsKey($col)) { continue }
            $f = $colToField[$col]
            $v = [string]$cells[$col]
            $old = ''
            if ($rec.PSObject.Properties.Name -contains $f) { $old = [string]$rec.$f }
            if ($old -ne $v) {
                if ($f -eq 'Output' -and $v -match '\[TRUNCATED - see Output File column\]') { continue }
                Add-Member -InputObject $rec -MemberType NoteProperty -Name $f -Value $v -Force
                $changed++
            }
        }
        [void]$newList.Add($rec)
    }

    Save-JournalRecords -Base $Base -Records $newList
    Write-T "  Imported $($newList.Count) row(s); $changed field change(s) applied to the journal." 'Ok'
    [void](Export-SessionWorkbook -Base $Base -Quiet)
    return $true
}

# ============================================================================
#  SESSION VARIABLE MEMORY
# ============================================================================
#
#  Two jobs:
#   1. Make assignments persist. Commands are dot-sourced inside
#      Invoke-RecordedCommand, so anything they assign lives in THAT function's
#      scope and dies when it returns - $TOKEN = "x" was being lost before the
#      next prompt. Newly created variables are promoted to global afterwards,
#      which is what makes the wrapper behave like a real shell.
#   2. Journal them, so ":variables" and the workbook show what was held and
#      which command set it.
# ============================================================================

$script:SessionVars = [ordered]@{}

# Variables whose VALUE is masked in :variables and never written to disk.
$script:SensitiveVarRx = '(?i)(pass|pwd|secret|token|cred|key|bearer|auth|sas|signature|connstr|connectionstring|private|session)'

# Recorder internals that must never be mistaken for operator variables.
$script:InternalVarRx = '^(sb|t|seg|line|captured|stderrLines|pipelineOk|interactive|errBefore|exitCode|newErrors|stderrOnly|net|outputText|stderrText|verdict|outFile|dir|intention|principal|authType|srcIp|notes|rec|style|ctx|startLocal|startUtc|sw|msg|e|fq|cat|n|assigned|prV|prM|prName|prVarsBefore|Base|CommandText|StickyIntent|Meta|Passthrough|_|args|input|PSBoundParameters|MyInvocation|PSCmdlet|PSCommandPath|PSScriptRoot|foreach|switch|this)$'

# PowerShell's own automatic and read-only variables. Promoting one of these to
# global would either throw or damage the host, so they are never touched even
# if the operator's command happens to create a local with the same name.
$script:ProtectedVarRx = '^(Host|ExecutionContext|PID|PSVersionTable|PWD|Error|StackTrace|PSHOME|ShellId|HOME|null|true|false|Profile|ConsoleFileName|NestedPromptLevel|OutputEncoding|PSCulture|PSUICulture|PSEdition|IsWindows|IsLinux|IsMacOS|IsCoreCLR|LASTEXITCODE|Matches|PSItem|PSDefaultParameterValues|ErrorActionPreference|ProgressPreference|VerbosePreference|DebugPreference|WarningPreference|InformationPreference|ConfirmPreference|WhatIfPreference)$'

function Get-VarsPath { param([string]$Base) Join-Path $Base 'variables.json' }

function Format-VarValue {
    param($Value, [int]$Max = 200)
    if ($null -eq $Value) { return '$null' }
    $t = ''
    try {
        if ($Value -is [string]) { $t = $Value }
        elseif ($Value -is [System.Collections.IDictionary]) {
            $parts = @(); $n = 0
            foreach ($k in $Value.Keys) { $parts += "$k=$($Value[$k])"; $n++; if ($n -ge 20) { $parts += '...'; break } }
            $t = '@{' + ($parts -join '; ') + '}'
        }
        elseif ($Value -is [System.Collections.IEnumerable]) {
            $parts = @(); $n = 0
            foreach ($it in $Value) { $parts += [string]$it; $n++; if ($n -ge 20) { $parts += '...'; break } }
            $t = '@(' + ($parts -join ', ') + ')'
        }
        else { $t = [string]$Value }
    } catch { $t = '<value could not be rendered>' }
    $t = Remove-AnsiAndControl $t
    $t = $t -replace "`r`n", ' ' -replace "`n", ' '
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + "...[$($t.Length) chars total]" }
    return $t
}

function Test-RestorableVar {
    param($Value)
    if ($null -eq $Value) { return $true }
    return ($Value -is [string] -or $Value -is [int] -or $Value -is [long] -or
            $Value -is [double] -or $Value -is [decimal] -or $Value -is [bool])
}

function Get-TrackedVarValue {
    param([string]$Name)
    if ($Name -like 'env:*') {
        return [Environment]::GetEnvironmentVariable($Name.Substring(4), 'Process')
    }
    $v = Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
    if ($v) { return $v.Value }
    return $null
}

function Update-SessionVariable {
    param([string]$Name, $Value, [int]$RowId, [string]$Command, [datetime]$When)

    $sensitive = [bool]($Name -match $script:SensitiveVarRx)
    $entry = $null
    if ($script:SessionVars.Contains($Name)) { $entry = $script:SessionVars[$Name] }
    if (-not $entry) {
        $entry = [ordered]@{ Name = $Name; FirstSet = (Format-Stamp $When); Changes = 0 }
        $script:SessionVars[$Name] = $entry
    }

    $rendered = Format-VarValue -Value $Value -Max 4000
    $len = if ($Value -is [string]) { $Value.Length } else { $rendered.Length }

    # Index syntax, not property syntax: adding a NEW key to an OrderedDictionary
    # through the property adapter is not reliable across PowerShell versions.
    $entry['Type']       = $(if ($null -eq $Value) { 'null' } else { $Value.GetType().Name })
    $entry['Length']     = $len
    # A variable whose NAME looks like a credential never has its value written
    # to disk. The live value is still readable in-session via ":variables <name>".
    $entry['Value']      = $(if ($sensitive) { "***masked ($len chars) - use ':variables $Name' to reveal in-session***" } else { $rendered })
    $entry['Raw']        = $(if ((-not $sensitive) -and (Test-RestorableVar $Value)) { $Value } else { $null })
    $entry['Restorable'] = ((-not $sensitive) -and (Test-RestorableVar $Value))
    $entry['Sensitive']  = $sensitive
    $entry['LastSet']    = (Format-Stamp $When)
    $entry['SetAtRow']   = $RowId
    $entry['SetBy']      = $(if ($Command.Length -gt 300) { $Command.Substring(0, 300) + '...' } else { $Command })
    $entry['Changes']    = [int]$entry['Changes'] + 1
}

function Save-SessionVariables {
    param([string]$Base)
    try {
        $arr = @()
        foreach ($k in $script:SessionVars.Keys) { $arr += [pscustomobject]$script:SessionVars[$k] }
        $json = ConvertTo-Json -InputObject @($arr) -Depth 6
        Set-Content -LiteralPath (Get-VarsPath $Base) -Value $json -Encoding UTF8
    } catch { }
}

function Get-SessionVariableRecords {
    param([string]$Base)
    $p = Get-VarsPath $Base
    if (-not (Test-Path -LiteralPath $p)) { return ,@() }
    try {
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($raw) { $raw = $raw -replace '^\uFEFF', '' }
        if (-not ($raw -and $raw.Trim())) { return ,@() }
        return ,@($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch { return ,@() }
}

function Restore-SessionVariables {
    param([string]$Base, [switch]$IntoShell)
    # Always reset first: without this, variables from a previous session in the
    # same program run would bleed into the one being opened.
    $script:SessionVars = [ordered]@{}
    $restored = 0; $skipped = 0
    foreach ($v in (Get-SessionVariableRecords -Base $Base)) {
        if (-not $v.Name) { continue }
        $e = [ordered]@{}
        foreach ($pp in $v.PSObject.Properties) { $e[$pp.Name] = $pp.Value }
        $script:SessionVars[[string]$v.Name] = $e
        if ($IntoShell) {
            if ($v.Restorable -and $v.Name -notlike 'env:*') {
                try { Set-Variable -Name ([string]$v.Name) -Value $v.Raw -Scope Global -Force -ErrorAction Stop; $restored++ }
                catch { $skipped++ }
            }
            elseif ($IntoShell -and $v.Restorable -and $v.Name -like 'env:*') {
                try { [Environment]::SetEnvironmentVariable($v.Name.Substring(4), [string]$v.Raw, 'Process'); $restored++ }
                catch { $skipped++ }
            }
            else { $skipped++ }
        }
    }
    return [pscustomobject]@{ Restored = $restored; Skipped = $skipped; Total = $script:SessionVars.Count }
}

function Show-SessionVariables {
    param([string]$Filter = '')

    if ($script:SessionVars.Count -eq 0) {
        Write-T '  No variables have been assigned in this session yet.' 'Dim'
        return
    }

    if ($Filter) {
        $want = $Filter.Trim().TrimStart('$')
        $key = ($script:SessionVars.Keys | Where-Object { $_ -ieq $want } | Select-Object -First 1)
        if (-not $key) { Write-T "  No variable named '$want' recorded in this session." 'Err'; return }
        $e = $script:SessionVars[$key]
        Write-T ''
        Write-T "  `$$key" 'Accent'
        foreach ($f in @('Type','Length','Changes','FirstSet','LastSet','SetAtRow','Sensitive','Restorable')) {
            if ($e.Contains($f)) { Write-T ("    {0,-11}: {1}" -f $f, $e[$f]) 'Text' }
        }
        if ($e.Contains('SetBy')) { Write-T ("    {0,-11}: {1}" -f 'SetBy', ($e['SetBy'] -replace "`r?`n", ' | ')) 'Dim' }
        # Read the value from the LIVE shell, never from disk - that is what lets
        # masked variables stay off disk while still being inspectable here.
        $live = Get-Variable -Name $key -Scope Global -ErrorAction SilentlyContinue
        if ($key -like 'env:*') {
            Write-T ("    {0,-11}: {1}" -f 'Value', (Format-VarValue -Value (Get-TrackedVarValue $key) -Max 2000)) 'Ok'
        }
        elseif ($live) {
            Write-T ("    {0,-11}: {1}" -f 'Value', (Format-VarValue -Value $live.Value -Max 2000)) 'Ok'
        }
        else {
            Write-T ("    {0,-11}: {1}" -f 'Value', $e['Value']) 'Warn'
            Write-T '                 (not present in the current shell)' 'Warn'
        }
        Write-T ''
        return
    }

    Write-T ''
    Write-T ("  {0,-20} {1,-12} {2,-7} {3,-17} {4,-5} {5}" -f 'Name','Type','Len','Last Set','Row','Value') 'Accent'
    Write-T '  ------------------------------------------------------------------------------' 'Dim'
    foreach ($k in $script:SessionVars.Keys) {
        $e = $script:SessionVars[$k]
        $val = [string]$e['Value']
        if ($val.Length -gt 40) { $val = $val.Substring(0, 37) + '...' }
        $style = if ($e['Sensitive']) { 'Warn' } else { 'Text' }
        Write-T ("  {0,-20} {1,-12} {2,-7} {3,-17} {4,-5} {5}" -f ('$' + $k), $e['Type'], $e['Length'], $e['LastSet'], $e['SetAtRow'], $val) $style
    }
    Write-T '  ------------------------------------------------------------------------------' 'Dim'
    Write-T "  $($script:SessionVars.Count) variable(s).  ':variables <name>' for one in full." 'Dim'
    Write-T ''
}

# ============================================================================
#  RECORDING LOOP
# ============================================================================

function Show-SessionHelp {
    Write-T ''
    Write-T '  Recorder meta-commands (not executed, not sent to the cloud):' 'Accent'
    Write-T '    exit session          Stop recording and return to the main menu' 'Text'
    Write-T '    :help                 This help' 'Text'
    Write-T '    :intent <text>        Set a sticky intention applied to following commands' 'Text'
    Write-T '    :intent               Clear the sticky intention (revert to auto-classification)' 'Text'
    Write-T '    :note <text>          Attach a note to the LAST recorded command' 'Text'
    Write-T '    :api <text>           Override the API Used value on the LAST command' 'Text'
    Write-T '    :fix <field> <value>  Override any field on the LAST command' 'Text'
    Write-T '    :last [n]             Show the last n recorded rows (default 5)' 'Text'
    Write-T '    :raw <command>        Run with a real console (interactive prompts / TUIs)' 'Text'
    Write-T '    :sync                 Re-render the XLSX now' 'Text'
    Write-T '    :pause / :resume      Suspend / resume recording (commands still execute)' 'Text'
    Write-T '    :auth                 Re-read local AWS/Azure auth context' 'Text'
    Write-T '    :info                 Show session file paths and counters' 'Text'
    Write-T '    :variables            Table of every variable assigned this session' 'Text'
    Write-T '    :variables <name>     One variable in full (reveals masked values)' 'Text'
    Write-T ''
    Write-T '  Multi-line: an unfinished command (open block, quote, here-string,' 'Dim'
    Write-T '  trailing pipe or backtick) keeps prompting with >> until it parses.' 'Dim'
    Write-T '  An empty line abandons the continuation.' 'Dim'
    Write-T ''
    Write-T '  Variables you assign persist across commands and are journalled.' 'Dim'
    Write-T '  Names that look like credentials are masked on disk, not in-session.' 'Dim'
    Write-T ''
}

function Invoke-RecordedCommand {
    param(
        [string]$Base,
        [string]$CommandText,
        [string]$StickyIntent,
        $Meta,
        [switch]$Passthrough
    )

    $ctx = Resolve-CommandContext -Command $CommandText

    Start-ConnectionSampler

    $startLocal = Get-Date
    $startUtc   = $startLocal.ToUniversalTime()
    $sw         = [Diagnostics.Stopwatch]::StartNew()

    $errBefore = $global:Error.Count
    $global:LASTEXITCODE = 0
    $captured    = New-Object System.Collections.Generic.List[string]
    $stderrLines = New-Object System.Collections.Generic.List[string]
    $pipelineOk  = $true

    # Anything that prompts or paints a TUI must own the console; piping its
    # output through Out-String buffers the prompt and the command appears to hang.
    $interactive = $Passthrough -or ($CommandText -imatch $script:InteractiveRx)

    # Names present in THIS scope before the command runs. Anything new
    # afterwards was created by the operator's command.
    $prVarsBefore = @{}
    foreach ($prV in (Get-Variable -Scope 0 -ErrorAction SilentlyContinue)) { $prVarsBefore[$prV.Name] = $true }

    try {
        $sb = [scriptblock]::Create($CommandText)
        if ($interactive) {
            . $sb
            [void]$captured.Add('(interactive passthrough - console output not captured; command, exit code, timing and network were recorded)')
        }
        else {
            # Reduce every ErrorRecord to its message BEFORE it reaches Out-String.
            # Otherwise a single stderr line from aws/node/git is rendered as a
            # multi-line "At line:1 char:5 / + CategoryInfo ..." block that both
            # pollutes the Output column and trips the error-signature scan.
            . $sb 2>&1 |
                ForEach-Object {
                    if ($_ -is [System.Management.Automation.ErrorRecord]) {
                        $t = if ($_.Exception -and $_.Exception.Message) { [string]$_.Exception.Message } else { [string]$_ }
                        foreach ($seg in ($t -split "`r?`n")) { [void]$stderrLines.Add($seg) }
                        $t
                    }
                    else { $_ }
                } |
                Out-String -Stream -Width 8192 |
                ForEach-Object {
                    $line = [string]$_
                    [void]$captured.Add($line)
                    if ($script:VT -and $script:UseTheme) { [Console]::WriteLine((Get-Sgr 'Text') + (Remove-AnsiAndControl $line)) }
                    else { Write-Host $line }
                }
        }
        $pipelineOk = $?
    }
    catch {
        $msg = $_.Exception.Message
        [void]$captured.Add($msg)
        Write-T $msg 'Err'
        $pipelineOk = $false
    }

    $sw.Stop()
    Reset-ThemeSgr

    # Promote variables the command created out of this function's scope and into
    # global, otherwise they die here and $NAME = "x" never survives to the next
    # prompt. This is what makes the wrapper behave like a real shell.
    $assigned = @()
    foreach ($prV in (Get-Variable -Scope 0 -ErrorAction SilentlyContinue)) {
        $prName = $prV.Name
        if ($prVarsBefore.ContainsKey($prName)) { continue }
        if ($prName -match $script:InternalVarRx) { continue }
        if ($prName -match $script:ProtectedVarRx) { continue }
        try {
            Set-Variable -Name $prName -Value $prV.Value -Scope Global -Force -ErrorAction Stop
            if ($assigned -notcontains $prName) { $assigned += $prName }
        } catch { }
    }
    # Explicit $global:/$script: assignments and $env: writes never appear as new
    # locals, so pick those out of the command text as well.
    foreach ($prM in [regex]::Matches($CommandText, '\$(?:global:|script:)([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)')) {
        $prName = $prM.Groups[1].Value
        if ($assigned -notcontains $prName) { $assigned += $prName }
    }
    foreach ($prM in [regex]::Matches($CommandText, '\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)')) {
        $prName = 'env:' + $prM.Groups[1].Value
        if ($assigned -notcontains $prName) { $assigned += $prName }
    }

    $exitCode = 0
    if ($null -ne $global:LASTEXITCODE) { $exitCode = [int]$global:LASTEXITCODE }

    # PowerShell wraps EVERY native stderr write in a NativeCommandError record,
    # so tools that log progress or warnings to stderr (node, aws-azure-login,
    # terraform, git) would otherwise be scored as failures. Those records are
    # stderr text, not failures - only exit code and real exceptions decide.
    $newErrors  = @()
    $stderrOnly = 0
    if ($global:Error.Count -gt $errBefore) {
        $n = $global:Error.Count - $errBefore
        foreach ($e in $global:Error[0..($n - 1)]) {
            $fq = ''
            try { $fq = [string]$e.FullyQualifiedErrorId } catch { }
            $cat = ''
            try { $cat = [string]$e.CategoryInfo.Reason } catch { }
            if ($fq -match 'NativeCommandError' -or $cat -eq 'RemoteException') { $stderrOnly++; continue }
            $newErrors += [string]$e
        }
    }
    # $? is unreliable for the same reason - a stderr write clears it.
    if ($exitCode -eq 0 -and $newErrors.Count -eq 0) { $pipelineOk = $true }

    $net = Stop-ConnectionSampler -PreferredEndpoint $ctx.Endpoint

    $outputText = (Remove-AnsiAndControl (($captured -join "`r`n").TrimEnd()))
    $stderrText = (Remove-AnsiAndControl (($stderrLines -join "`r`n").TrimEnd()))
    $verdict = Resolve-CommandResult -Output $outputText -Stderr $stderrText -ExitCode $exitCode -NewErrors $newErrors -PipelineOk $pipelineOk

    # Long outputs go to a sidecar file.
    $outFile = ''
    if ($outputText.Length -gt $script:MaxCellChars) {
        $dir = Get-OutputsPath $Base
        if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $outFile = Join-Path $dir ("row_{0:0000}.txt" -f [int]$Meta.NextRowId)
        Set-Content -Path $outFile -Value $outputText -Encoding UTF8
    }

    $intention = if ($StickyIntent) { $StickyIntent } elseif ($ctx.Intent) { $ctx.Intent } else { '(not set)' }

    $principal = ''
    $authType  = ''
    switch ($ctx.Cloud) {
        'AWS'   { $principal = [string]$Meta.AwsPrincipal; $authType = [string]$Meta.AwsAuthType }
        'Azure' { $principal = [string]$Meta.AzPrincipal;  $authType = [string]$Meta.AzAuthType }
        default { $principal = [string]$Meta.OsUser;       $authType = 'Local shell' }
    }

    $srcIp = $net.SrcIP
    if ([string]$Meta.PublicEgressIp) {
        $srcIp = if ($srcIp) { "$($Meta.PublicEgressIp) (egress) / $srcIp (local)" } else { "$($Meta.PublicEgressIp) (egress)" }
    }

    $notes = @()
    if ($net.Note) { $notes += $net.Note }
    if ($ctx.Region) { $notes += "region=$($ctx.Region)" }
    if ($stderrOnly -gt 0) { $notes += "$stderrOnly stderr write(s) treated as warnings, not failures" }
    if ($interactive) { $notes += 'interactive passthrough' }
    if ($assigned.Count -gt 0) {
        foreach ($prName in $assigned) {
            Update-SessionVariable -Name $prName -Value (Get-TrackedVarValue $prName) `
                                   -RowId ([int]$Meta.NextRowId) -Command $CommandText -When $startLocal
        }
        Save-SessionVariables -Base $Base
        $notes += 'set: ' + (($assigned | ForEach-Object { '$' + $_ }) -join ', ')
    }

    $rec = New-EmptyRecord
    $rec.RowId      = [int]$Meta.NextRowId
    $rec.LocalTime  = Format-Stamp $startLocal
    $rec.UtcTime    = Format-Stamp $startUtc
    $rec.Command    = $CommandText
    $rec.Result     = $verdict.Result
    $rec.Reason     = $verdict.Reason
    $rec.Output     = $outputText
    $rec.SrcIP      = $srcIp
    $rec.SrcPort    = $net.SrcPort
    $rec.DstIP      = $net.DstIP
    $rec.DstPort    = $net.DstPort
    $rec.LogonType  = [string]$Meta.LogonType
    $rec.Api        = $ctx.Api
    $rec.Intention  = $intention
    $rec.Cloud      = $ctx.Cloud
    $rec.Principal  = $principal
    $rec.AuthType   = $authType
    $rec.Attack     = $ctx.Attack
    $rec.ExitCode   = [string]$exitCode
    $rec.DurationMs = [string]$sw.ElapsedMilliseconds
    $rec.Hostname   = [string]$Meta.Machine
    $rec.OsUser     = [string]$Meta.OsUser
    $rec.OutputFile = $outFile
    $rec.Notes      = ($notes -join '; ')

    Add-JournalRecord -Base $Base -Record ([pscustomobject]$rec)

    $Meta.NextRowId = [int]$Meta.NextRowId + 1
    Save-SessionMeta -Base $Base -Meta $Meta

    $style = if ($verdict.Result -eq 'Error') { 'Err' } else { 'Ok' }
    Write-T ("  [#{0}] {1} | {2} | {3}ms | {4}" -f $rec.RowId, $verdict.Result, ($(if ($ctx.Api) { $ctx.Api } else { 'n/a' })), $sw.ElapsedMilliseconds, $verdict.Reason) $style
    if ($net.DstIP) {
        Write-T ("        net: {0}:{1} -> {2}:{3}" -f $(if ($net.SrcIP) { $net.SrcIP } else { '?' }), $(if ($net.SrcPort) { $net.SrcPort } else { '?' }), $net.DstIP, $net.DstPort) 'Dim'
    }
    if ($assigned.Count -gt 0) {
        Write-T ("        vars: " + (($assigned | ForEach-Object { '$' + $_ }) -join ', ')) 'Dim'
    }
    return $rec
}

function Start-RecordingLoop {
    param([string]$Base)

    $meta = Get-SessionMeta -Base $Base
    Set-WindowTitle "REC: $($meta.Name)"
    Write-Banner "Recording session: $($meta.Name)"
    Write-T "  Folder  : $Base" 'Dim'
    Write-T "  Workbook: $(Get-XlsxPath $Base)"  'Dim'
    Write-T "  Identity: $($meta.OsUser)  |  Logon: $($meta.LogonType)" 'Dim'
    if ($meta.AwsAuthType) { Write-T "  AWS     : $($meta.AwsPrincipal)  [$($meta.AwsAuthType)]" 'Dim' }
    if ($meta.AzAuthType)  { Write-T "  Azure   : $($meta.AzPrincipal)  [$($meta.AzAuthType)]" 'Dim' }
    $vr = Restore-SessionVariables -Base $Base -IntoShell
    if ($vr.Total -gt 0) {
        Write-T "  Vars    : $($vr.Total) recorded, $($vr.Restored) restored into the shell, $($vr.Skipped) not restorable" 'Dim'
    }
    Write-T ''
    Write-T '  Type "exit session" to stop. ":help" for recorder commands.' 'Accent'
    Write-T ''

    $sticky   = ''
    $paused   = $false
    $xlsxLockWarned = $false
    $lastRec  = $null

    while ($true) {
        $cwd = (Get-Location).Path
        $flag = if ($paused) { 'UV PAUSED' } else { 'UV' }
        $flagStyle = if ($paused) { 'Warn' } else { 'Ok' }
        Write-T ''
        Write-T "[$flag $($meta.Name)] $cwd" $flagStyle
        $line = Read-CommandLine -Prompt '> '

        if ($null -eq $line) { continue }
        $trim = $line.Trim()
        if (-not $trim) { continue }

        # ---- meta-commands ----
        if ($trim -match '^(?i)exit\s+session$') {
            Write-T ''
            Write-T '  Closing session and rendering workbook...' 'Warn'
            [void](Export-SessionWorkbook -Base $Base)
            Save-SessionMeta -Base $Base -Meta $meta
            Pause-Key
            return
        }
        $forceRaw = $false
        if ($trim -imatch '^:raw\s+(.+)$') { $forceRaw = $true; $trim = $Matches[1].Trim() }

        if (-not $forceRaw -and $trim.StartsWith(':')) {
            $parts = $trim.Substring(1).Split(@(' '), 2, [StringSplitOptions]::RemoveEmptyEntries)
            if ($parts.Count -eq 0) { Write-T '  Empty recorder command.' 'Err'; continue }
            $verb  = $parts[0].ToLower()
            $arg   = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }

            switch ($verb) {
                'help'   { Show-SessionHelp; continue }
                'pause'  { $paused = $true;  Write-T '  Recording PAUSED - commands will execute but not be journalled.' 'Warn'; continue }
                'resume' { $paused = $false; Write-T '  Recording RESUMED.' 'Ok'; continue }
                'sync'   { [void](Export-SessionWorkbook -Base $Base); $xlsxLockWarned = $false; continue }
                'intent' {
                    $sticky = $arg
                    if ($sticky) { Write-T "  Sticky intention set: $sticky" 'Ok' }
                    else { Write-T '  Sticky intention cleared (auto-classification resumes).' 'Ok' }
                    continue
                }
                'auth' {
                    $a = Get-CloudAuthContext
                    $meta.AwsPrincipal = $a.AwsPrincipal; $meta.AwsAuthType = $a.AwsAuthType
                    $meta.AzPrincipal  = $a.AzPrincipal;  $meta.AzAuthType  = $a.AzAuthType
                    Save-SessionMeta -Base $Base -Meta $meta
                    Write-T "  AWS  : $($a.AwsPrincipal) [$($a.AwsAuthType)]" 'Ok'
                    Write-T "  Azure: $($a.AzPrincipal) [$($a.AzAuthType)]" 'Ok'
                    continue
                }
                { $_ -in @('variables','vars','var') } {
                    Show-SessionVariables -Filter $arg
                    continue
                }
                'info' {
                    $recs = Get-JournalRecords -Base $Base
                    Write-T "  Session   : $($meta.Name)" 'Text'
                    Write-T "  Records   : $($recs.Count)" 'Text'
                    Write-T "  Journal   : $(Get-JournalPath $Base)" 'Text'
                    Write-T "  Workbook  : $(Get-XlsxPath $Base)" 'Text'
                    Write-T "  Outputs   : $(Get-OutputsPath $Base)" 'Text'
                    Write-T "  Variables : $($script:SessionVars.Count)   (:variables to list)" 'Text'
                    Write-T "  Sticky    : $(if ($sticky) { $sticky } else { '(none)' })" 'Text'
                    continue
                }
                'last' {
                    $n = 5; if ($arg -match '^\d+$') { $n = [int]$arg }
                    $recs = Get-JournalRecords -Base $Base
                    $show = $recs | Select-Object -Last $n
                    Write-T ''
                    foreach ($r in $show) {
                        $st = if ($r.Result -eq 'Error') { 'Err' } else { 'Ok' }
                        Write-T ("  #{0} {1} [{2}] {3}" -f $r.RowId, $r.LocalTime, $r.Result, $r.Command) $st
                        Write-T ("      api={0} | intent={1}" -f $r.Api, $r.Intention) 'Dim'
                    }
                    Write-T ''
                    continue
                }
                { $_ -in @('note','api','fix') } {
                    $recs = Get-JournalRecords -Base $Base
                    if ($recs.Count -eq 0) { Write-T '  Nothing recorded yet.' 'Err'; continue }
                    $target = $recs[$recs.Count - 1]
                    if ($verb -eq 'note') {
                        $prev = [string]$target.Notes
                        $target.Notes = if ($prev) { "$prev; $arg" } else { $arg }
                        Write-T "  Note added to #$($target.RowId)." 'Ok'
                    }
                    elseif ($verb -eq 'api') {
                        $target.Api = $arg
                        Write-T "  API Used on #$($target.RowId) set to: $arg" 'Ok'
                    }
                    else {
                        $fp = $arg.Split(@(' '), 2, [StringSplitOptions]::RemoveEmptyEntries)
                        if ($fp.Count -lt 2) { Write-T '  Usage: :fix <Field> <value>' 'Err'; continue }
                        $field = ($script:EditableFields | Where-Object { $_ -ieq $fp[0] } | Select-Object -First 1)
                        if (-not $field) { Write-T "  Unknown/locked field. Editable: $($script:EditableFields -join ', ')" 'Err'; continue }
                        Add-Member -InputObject $target -MemberType NoteProperty -Name $field -Value $fp[1] -Force
                        Write-T "  #$($target.RowId).$field updated." 'Ok'
                    }
                    Save-JournalRecords -Base $Base -Records $recs
                    continue
                }
                default { Write-T "  Unknown recorder command ':$verb'. Try :help" 'Err' }
            }
            # NOTE: 'continue' inside a switch only ends the switch, it does NOT
            # continue the enclosing loop. Without this, every meta-command fell
            # through and was executed as a shell command.
            continue
        }

        # ---- multi-line continuation ----
        # Meta-commands were dispatched above, so anything reaching here is a real
        # command and may legitimately span lines.
        $trim = (Read-ContinuedCommandLine -First $trim).Trim()
        if (-not $trim) { continue }

        # ---- execute ----
        if ($paused) {
            try {
                $sb = [scriptblock]::Create($trim)
                . $sb 2>&1 | Out-String -Stream -Width 8192 | ForEach-Object { Write-Host $_ }
            } catch { Write-T $_.Exception.Message 'Err' }
            Reset-ThemeSgr
            continue
        }

        $lastRec = Invoke-RecordedCommand -Base $Base -CommandText $trim -StickyIntent $sticky -Meta $meta -Passthrough:$forceRaw

        # Refresh the workbook immediately so it never lags the journal.
        if (Export-SessionWorkbook -Base $Base -Quiet) {
            $xlsxLockWarned = $false
        }
        elseif (-not $xlsxLockWarned) {
            Write-T '  [xlsx] Workbook not written - is it open in Excel? The journal is still' 'Warn'
            Write-T '         being saved; close the file, then :sync to catch the workbook up.' 'Warn'
            $xlsxLockWarned = $true
        }
    }
}

# ============================================================================
#  MENU: SESSION PICKER
# ============================================================================

function Select-Session {
    param([string]$Title = 'Choose a session')

    $sessions = Get-SessionList
    if ($sessions.Count -eq 0) {
        Write-T '  No sessions found.' 'Err'
        Show-SkippedFolders
        Pause-Key
        return $null
    }

    Write-T ''
    Write-T "  $Title" 'Accent'
    Write-T '  ---------------------------------------------------------------------------' 'Dim'
    for ($i = 0; $i -lt $sessions.Count; $i++) {
        $s = $sessions[$i]
        Write-T ("   {0,3}. {1}" -f ($i + 1), $s.BaseName) 'Text'
        Write-T ("        created {0} | {1} record(s) | {2}" -f $s.Created, $s.Records, $s.User) 'Dim'
    }
    Write-T '  ---------------------------------------------------------------------------' 'Dim'
    $a = Read-Answer '  Number (or blank to cancel): '
    if (-not $a) { return $null }
    if ($a -notmatch '^\d+$') { Write-T '  Invalid selection.' 'Err'; Pause-Key; return $null }
    $idx = [int]$a - 1
    if ($idx -lt 0 -or $idx -ge $sessions.Count) { Write-T '  Out of range.' 'Err'; Pause-Key; return $null }
    return $sessions[$idx]
}

# ============================================================================
#  MENU ACTIONS
# ============================================================================

function Invoke-CreateSession {
    Write-Banner 'Create new session'
    $name = Read-Answer '  Session name: '
    if (-not $name) { Write-T '  Cancelled - a name is required.' 'Err'; Pause-Key; return }

    $base = New-SessionFiles -Name $name
    $meta = Get-SessionMeta -Base $base

    Write-T ''
    Write-T "  Created: $(Split-Path $base -Leaf)" 'Ok'
    Write-T "  Folder : $base" 'Dim'
    Write-T ''

    if (Confirm-YesNo 'Look up the public egress IP now? (single outbound HTTPS request to an IP-echo service)' $false) {
        Write-T '  Resolving...' 'Dim'
        $ip = Get-PublicEgressIp
        if ($ip) { $meta.PublicEgressIp = $ip; Save-SessionMeta -Base $base -Meta $meta; Write-T "  Egress IP: $ip" 'Ok' }
        else { Write-T '  Could not determine egress IP (blocked or offline).' 'Warn' }
    }

    [void](Export-SessionWorkbook -Base $base -Quiet)

    Write-T ''
    if (Confirm-YesNo 'Continue to session?' $true) {
        Start-RecordingLoop -Base $base
    }
}

function Invoke-ResumeSession {
    Write-Banner 'Resume session'
    $s = Select-Session -Title 'Sessions available to resume'
    if (-not $s) { return }
    # Refresh volatile host context on resume; keeps records accurate across RDP hops.
    $meta = Get-SessionMeta -Base $s.Base
    $meta.LogonType = Get-WindowsLogonType
    $meta.Machine   = $env:COMPUTERNAME
    $meta.OsUser    = "$env:USERDOMAIN\$env:USERNAME"
    $a = Get-CloudAuthContext
    $meta.AwsPrincipal = $a.AwsPrincipal; $meta.AwsAuthType = $a.AwsAuthType
    $meta.AzPrincipal  = $a.AzPrincipal;  $meta.AzAuthType  = $a.AzAuthType
    Save-SessionMeta -Base $s.Base -Meta $meta
    Start-RecordingLoop -Base $s.Base
}

function Show-RecordDetail {
    param($Record)
    Write-T ''
    Write-T "  ---- Record #$($Record.RowId) ----" 'Accent'
    $i = 0
    foreach ($k in $script:Schema.Keys) {
        $i++
        $v = ''
        if ($Record.PSObject.Properties.Name -contains $k) { $v = [string]$Record.$k }
        if ($k -eq 'Output' -and $v.Length -gt 600) { $v = $v.Substring(0, 600) + " ...[$($v.Length) chars total]" }
        $v = $v -replace "`r`n", ' | ' -replace "`n", ' | '
        $lockTag = if ($script:EditableFields -contains $k) { ' ' } else { '*' }
        Write-T ("  {0,2}{1} {2,-14} : {3}" -f $i, $lockTag, $script:Schema[$k], $v) 'Text'
    }
    Write-T '  (* = not editable)' 'Dim'
    Write-T ''
}

function Invoke-EditSession {
    Write-Banner 'Edit session'
    $s = Select-Session -Title 'Sessions available to view / edit'
    if (-not $s) { return }
    $base = $s.Base

    while ($true) {
        $recs = Get-JournalRecords -Base $base
        Write-Banner "Edit: $($s.BaseName)  ($($recs.Count) record(s))"

        $page = $recs | Select-Object -Last 25
        foreach ($r in $page) {
            $st = if ($r.Result -eq 'Error') { 'Err' } else { 'Ok' }
            $cmd = [string]$r.Command
            if ($cmd.Length -gt 88) { $cmd = $cmd.Substring(0, 85) + '...' }
            Write-T ("  #{0,-4} {1}  [{2,-7}] {3}" -f $r.RowId, $r.LocalTime, $r.Result, $cmd) $st
        }
        if ($recs.Count -gt 25) { Write-T "  ...showing last 25 of $($recs.Count)" 'Dim' }

        Write-T ''
        $errCount = @($recs | Where-Object { [string]$_.Result -eq 'Error' }).Count
        Write-T '  [row#] view/edit a record   [D row#] delete row   [X] export xlsx' 'Accent'
        Write-T '  [I] import edits made in Excel   [O row#] open full output   [B] back' 'Accent'
        Write-T "  [E] remove all error rows ($errCount)   [V] view recorded variables" 'Accent'
        $a = Read-Answer '  > '
        if (-not $a) { continue }

        if ($a -match '^(?i)b$') { return }

        if ($a -match '^(?i)x$') {
            [void](Export-SessionWorkbook -Base $base)
            Pause-Key; continue
        }

        if ($a -match '^(?i)v$') {
            $keep = $script:SessionVars
            [void](Restore-SessionVariables -Base $base)
            Show-SessionVariables
            $script:SessionVars = $keep   # do not clobber the live session's table
            Pause-Key; continue
        }

        if ($a -match '^(?i)e$') {
            $errs = @($recs | Where-Object { [string]$_.Result -eq 'Error' })
            if ($errs.Count -eq 0) { Write-T '  No rows are marked Error.' 'Ok'; Pause-Key; continue }
            Write-T ''
            Write-T "  $($errs.Count) row(s) marked Error:" 'Warn'
            foreach ($r in ($errs | Select-Object -First 15)) {
                $c = ([string]$r.Command) -replace "`r?`n", ' | '
                if ($c.Length -gt 76) { $c = $c.Substring(0, 73) + '...' }
                Write-T ("    #{0,-4} {1}" -f $r.RowId, $c) 'Warn'
            }
            if ($errs.Count -gt 15) { Write-T "    ...and $($errs.Count - 15) more" 'Warn' }
            Write-T ''
            Write-T '  Worth a thought first: a denied API call is evidence that a control' 'Dim'
            Write-T '  held, and is often the most useful row in a purple-team report.' 'Dim'
            if (Confirm-YesNo "Delete all $($errs.Count) error row(s)?" $false) {
                foreach ($r in $errs) {
                    if ($r.OutputFile -and (Test-Path -LiteralPath $r.OutputFile)) {
                        Remove-Item -LiteralPath $r.OutputFile -Force -ErrorAction SilentlyContinue
                    }
                }
                $kept = @($recs | Where-Object { [string]$_.Result -ne 'Error' })
                Save-JournalRecords -Base $base -Records $kept
                [void](Export-SessionWorkbook -Base $base -Quiet)
                Write-T "  Removed $($errs.Count) error row(s). $($kept.Count) remaining." 'Ok'
            }
            Pause-Key; continue
        }

        if ($a -match '^(?i)i$') {
            Write-T '  This overwrites journal fields with the workbook contents.' 'Warn'
            if (Confirm-YesNo 'Import edits from the XLSX into the journal?' $false) {
                [void](Import-SessionWorkbook -Base $base)
            }
            Pause-Key; continue
        }

        if ($a -match '^(?i)o\s+(\d+)$') {
            $rid = $Matches[1]
            $rec = $recs | Where-Object { [string]$_.RowId -eq $rid } | Select-Object -First 1
            if (-not $rec) { Write-T '  No such row.' 'Err'; Pause-Key; continue }
            $txt = if ($rec.OutputFile -and (Test-Path $rec.OutputFile)) { Get-Content $rec.OutputFile -Raw } else { [string]$rec.Output }
            Write-T ''
            Write-T "  ---- Output of #$rid ----" 'Accent'
            foreach ($l in ($txt -split "`r?`n")) { Write-T "  $l" 'Text' }
            Pause-Key; continue
        }

        if ($a -match '^(?i)d\s+(\d+)$') {
            $rid = $Matches[1]
            $rec = $recs | Where-Object { [string]$_.RowId -eq $rid } | Select-Object -First 1
            if (-not $rec) { Write-T '  No such row.' 'Err'; Pause-Key; continue }
            Write-T "  Row #$rid : $($rec.Command)" 'Warn'
            if (Confirm-YesNo "Delete record #$rid permanently?" $false) {
                $kept = $recs | Where-Object { [string]$_.RowId -ne $rid }
                Save-JournalRecords -Base $base -Records $kept
                if ($rec.OutputFile -and (Test-Path $rec.OutputFile)) { Remove-Item $rec.OutputFile -Force -ErrorAction SilentlyContinue }
                [void](Export-SessionWorkbook -Base $base -Quiet)
                Write-T "  Record #$rid deleted." 'Ok'
            }
            Pause-Key; continue
        }

        if ($a -match '^#?(\d+)$') {
            $rid = $Matches[1]
            $rec = $recs | Where-Object { [string]$_.RowId -eq $rid } | Select-Object -First 1
            if (-not $rec) { Write-T '  No such row.' 'Err'; Pause-Key; continue }

            while ($true) {
                Show-RecordDetail -Record $rec
                $f = Read-Answer '  Field number to edit (blank = back): '
                if (-not $f) { break }
                if ($f -notmatch '^\d+$') { Write-T '  Enter a field number.' 'Err'; continue }
                $keys = @($script:Schema.Keys)
                $fi = [int]$f - 1
                if ($fi -lt 0 -or $fi -ge $keys.Count) { Write-T '  Out of range.' 'Err'; continue }
                $field = $keys[$fi]
                if ($script:EditableFields -notcontains $field) { Write-T "  '$($script:Schema[$field])' is derived and cannot be edited." 'Err'; continue }

                $cur = ''
                if ($rec.PSObject.Properties.Name -contains $field) { $cur = [string]$rec.$field }
                Write-T "  Current: $cur" 'Dim'
                Write-T '  New value (single line; blank keeps current):' 'Accent'
                $nv = [Console]::ReadLine()
                if ([string]::IsNullOrEmpty($nv)) { Write-T '  Unchanged.' 'Dim'; continue }
                Add-Member -InputObject $rec -MemberType NoteProperty -Name $field -Value $nv -Force
                Save-JournalRecords -Base $base -Records $recs
                [void](Export-SessionWorkbook -Base $base -Quiet)
                Write-T "  Updated $($script:Schema[$field])." 'Ok'
            }
            continue
        }

        Write-T '  Unrecognised input.' 'Err'
        Pause-Key
    }
}

function Invoke-DeleteSession {
    Write-Banner 'Delete session'
    $s = Select-Session -Title 'Sessions available to delete'
    if (-not $s) { return }

    Write-T ''
    Write-T "  Session : $($s.BaseName)" 'Warn'
    Write-T "  Records : $($s.Records)" 'Warn'
    Write-T "  Folder  : $($s.Base)" 'Warn'
    Write-T ''
    if (-not (Confirm-YesNo 'Are you sure? The whole session folder is removed. This cannot be undone.' $false)) {
        Write-T '  Cancelled.' 'Ok'; Pause-Key; return
    }
    $typed = Read-Answer "  Type the session name ('$($s.Name)') to confirm: "
    if ($typed -ne $s.Name) { Write-T '  Name did not match - nothing deleted.' 'Err'; Pause-Key; return }

    try {
        Remove-Item -LiteralPath $s.Base -Recurse -Force -ErrorAction Stop
        Write-T '  Session deleted.' 'Ok'
    } catch {
        Write-T "  Could not delete: $($_.Exception.Message)" 'Err'
        Write-T '  If the workbook is open in Excel, close it and retry.' 'Warn'
    }
    Pause-Key
}

# ============================================================================
#  MAIN MENU
# ============================================================================

function Show-MainMenu {
    while ($true) {
        Set-WindowTitle 'Main menu'
        Write-Banner
        $sessions = Get-SessionList
        Write-T "  Data root : $script:DataRoot" 'Dim'
        Write-T "  Sessions  : $($sessions.Count)" 'Dim'
        Write-T "  Operator  : $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME" 'Dim'
        Write-T ''
        Write-T '   1)  Create New Session' 'Text'
        Write-T '   2)  Resume Session'     'Text'
        Write-T '   3)  Edit Session'       'Text'
        Write-T '   4)  Delete Session'     'Text'
        Write-T '   5)  Exit'               'Text'
        Write-T ''
        $c = Read-Answer '  Select [1-5]: '

        switch ($c) {
            '1' { Invoke-CreateSession }
            '2' { Invoke-ResumeSession }
            '3' { Invoke-EditSession }
            '4' { Invoke-DeleteSession }
            '5' {
                Write-T ''
                if (Confirm-YesNo 'Are you sure you want to exit?' $false) { return }
            }
            default { Write-T '  Choose 1-5.' 'Err'; Start-Sleep -Milliseconds 700 }
        }
    }
}

# ============================================================================
#  ENTRY POINT
# ============================================================================

try {
    Set-UltraVioletTheme
    Initialize-DataRoot
    Show-MainMenu
}
finally {
    if ($script:Sampler) { [void](Stop-ConnectionSampler) }
    Restore-Console
    Write-Host "$($script:AppName) closed. Sessions: $script:DataRoot" -ForegroundColor DarkMagenta
}
