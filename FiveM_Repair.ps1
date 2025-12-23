# =====================================================
#           FiveM Diagnostic & Repair Tool
# =====================================================
# Versión avanzada: Mejora en manejo de errores, validaciones, automatización y usabilidad.
# Requiere PowerShell 5+ y permisos de administrador para algunas funciones.

# Forzar codificación UTF-8 para evitar problemas con tildes
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReportTXT = "$BasePath\FiveM_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$ReportJSON = "$BasePath\FiveM_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$Global:Report = [ordered]@{ Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

# ---------------- UI ----------------
function Header {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "        FiveM Diagnostic & Repair Tool (PRO)       " -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
}
function Section($t){ Write-Host "`n[ $t ]" -ForegroundColor Yellow }
function OK($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function WARN($m){ Write-Host "[ !! ] $m" -ForegroundColor Yellow }
function FAIL($m){ Write-Host "[ XX ] $m" -ForegroundColor Red }
function Pause { Read-Host "Presiona ENTER para continuar" }
function Progress($step, $total) { Write-Host "Progreso: $step/$total completado" -ForegroundColor Magenta }

# ---------------- VALIDACIONES INICIALES ----------------
function Check-Admin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        FAIL "Este script requiere permisos de administrador para algunas funciones. Ejecuta como admin."
        Pause
        exit
    }
}
Check-Admin

# ---------------- GTA DETECTION (CORREGIDA PARA BUSCAR EN TODAS LAS UNIDADES) ----------------
function Detect-GTA {
    Section "Detección optimizada de GTA V"

    $found = @()
    $gtaExe = "GTA5.exe"

    # Carpetas típicas donde suele estar GTA
    $commonFolders = @(
        "Program Files",
        "Program Files (x86)",
        "Games",
        "Juegos",
        "Rockstar Games",
        "Steam",
        "Epic Games"
    )

    # Carpetas que NO deben escanearse
    $excludeFolders = @(
        "Windows",
        "ProgramData",
        "Users",
        "PerfLogs",
        "AppData",
        "System Volume Information",
        "`$Recycle.Bin"
    )

    $drives = Get-PSDrive -PSProvider FileSystem |
              Where-Object { $_.Free -gt 0 -and $_.Root -match "^[A-Z]:\\" }

    # ---------- FASE 1: BÚSQUEDA RÁPIDA ----------
    Write-Host "Fase 1: búsqueda rápida en rutas comunes..." -ForegroundColor Cyan

    foreach ($drive in $drives) {
        foreach ($folder in $commonFolders) {
            $path = Join-Path $drive.Root $folder
            if (Test-Path $path) {
                try {
                    $res = Get-ChildItem `
                        -Path $path `
                        -Filter $gtaExe `
                        -Recurse `
                        -Depth 5 `
                        -ErrorAction SilentlyContinue

                    if ($res) {
                        $found += $res.DirectoryName
                    }
                } catch {}
            }
        }
    }

    # ---------- FASE 2: ESCANEO PROFUNDO CONTROLADO ----------
    if ($found.Count -eq 0) {
        WARN "No encontrado en rutas comunes. Iniciando escaneo profundo controlado..."

        foreach ($drive in $drives) {
            try {
                Get-ChildItem `
                    -Path $drive.Root `
                    -Directory `
                    -ErrorAction SilentlyContinue |
                Where-Object { $excludeFolders -notcontains $_.Name } |
                ForEach-Object {
                    try {
                        $res = Get-ChildItem `
                            -Path $_.FullName `
                            -Filter $gtaExe `
                            -Recurse `
                            -Depth 4 `
                            -ErrorAction SilentlyContinue
                        if ($res) {
                            $found += $res.DirectoryName
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # ---------- RESULTADO ----------
    if ($found.Count -gt 0) {
        $unique = $found | Sort-Object -Unique
        OK "GTA V detectado en:"
        $unique | ForEach-Object { Write-Host " - $_" }

        # 🔴 CLAVE: guardar ruta REAL para el resto del script
        $Global:Report.GTAPath = $unique
        $Global:Report.GTA = "Detectado"
    } else {
        FAIL "GTA V no fue detectado en ningún disco"
        WARN "Verifica que GTA5.exe exista y que el disco esté accesible"
        $Global:Report.GTAPath = $null
        $Global:Report.GTA = "No detectado"
    }
}


# ---------------- CACHE ----------------
function Clean-FiveMCache {
    Section "Caché FiveM"
    $cache = "$env:LOCALAPPDATA\FiveM\FiveM.app\data\cache"
    if (Test-Path $cache){
        $confirm = Read-Host "¿Confirmar limpieza de caché? (S/N)"
        if ($confirm -eq 'S' -or $confirm -eq 's') {
            try {
                # Cerrar procesos relacionados
                Get-Process -Name "FiveM*", "GTA5" -ErrorAction SilentlyContinue | Stop-Process -Force
                Remove-Item "$cache\*" -Recurse -Force -ErrorAction Stop
                OK "Caché limpiada (procesos cerrados si era necesario)"
                WARN "Sugerencia: Ejecuta FiveM una vez para regenerar caché y actualizar logs."
                $Global:Report.Cache = "Limpia"
            } catch {
                FAIL "Error al limpiar caché: $_"
                $Global:Report.Cache = "Error: $_"
            }
        } else {
            WARN "Limpieza cancelada"
            $Global:Report.Cache = "Cancelada"
        }
    } else {
        WARN "Caché no encontrada"
        $Global:Report.Cache = "No encontrada"
    }
}

# ---------------- GPU ----------------
function Check-GPU {
    Section "GPU / Drivers"
    try {
        $gpus = Get-WmiObject Win32_VideoController -ErrorAction Stop
        $list = @()
        foreach ($g in $gpus){
            Write-Host "GPU: $($g.Name)"
            Write-Host "Driver: $($g.DriverVersion)"
            $list += @{ Name=$g.Name; Driver=$g.DriverVersion }
        }
        # Sugerencia básica de actualización
        if ($gpus.DriverVersion -match "^\d{4}\.\d{2}\.\d{2}\.\d{4}$") { # Ejemplo simple
            WARN "Considera actualizar drivers desde el sitio del fabricante."
        }
        $Global:Report.GPU = $list
    } catch {
        FAIL "Error al verificar GPU: $_"
        $Global:Report.GPU = "Error: $_"
    }
}

# ---------------- RAM ----------------
function Check-RAM {
    Section "RAM / Memoria Virtual"
    try {
        $ram = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB
        $page = (Get-CimInstance Win32_PageFileUsage -ErrorAction Stop).AllocatedBaseSize / 1024
        OK ("RAM: {0:N2} GB" -f $ram)
        OK ("Virtual: {0:N2} GB" -f $page)
        if ($ram -lt 8) { WARN "RAM baja: Recomendado al menos 8GB para FiveM." }
        $Global:Report.RAM = @{ RAM_GB=[math]::Round($ram,2); Virtual_GB=[math]::Round($page,2) }
    } catch {
        FAIL "Error al verificar RAM: $_"
        $Global:Report.RAM = "Error: $_"
    }
}

# ---------------- PORTS ----------------
function Test-Ports {
    Section "Puertos FiveM"
    $res = @{}
    foreach ($p in @(30120,30110)){
        try {
            $t = Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue -ErrorAction Stop
            Write-Host "Puerto ${p}: $($t.TcpTestSucceeded)"
            $res["$p"] = $t.TcpTestSucceeded
        } catch {
            FAIL "Error al probar puerto ${p}: $_"
            $res["$p"] = "Error: $_"
        }
    }
    $Global:Report.Ports = $res
}

# ---------------- FIREWALL ----------------
function Check-Firewall {
    Section "Firewall"
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $fw | ForEach-Object { Write-Host "$($_.Name): Enabled=$($_.Enabled)" }
        $Global:Report.Firewall = $fw | Select Name,Enabled
    } catch {
        FAIL "Error al verificar firewall: $_"
        $Global:Report.Firewall = "Error: $_"
    }
}

# ---------------- OVERLAYS ----------------
function Overlay-Warning {
    Section "Overlays"
    WARN "Desactiva manualmente:"
    Write-Host "- Discord Overlay"
    Write-Host "- NVIDIA / AMD Overlay"
    Write-Host "- MSI Afterburner"
    $Global:Report.Overlays = "Aviso mostrado"
}

# ---------------- ERROR CATALOG (REFINADO PARA EVITAR FALSOS POSITIVOS) ----------------
$FiveMErrorCatalog = @(
 @{Id="CACHE";Pattern="(?i)(error|failed).*cache.*(corrupt|full|invalid)";Fix="AUTO";Msg="Caché corrupta. Se puede limpiar automáticamente."},
 @{Id="GPU";Pattern="(?i)(error|failed|dxgi|d3d).*gpu|driver.*failed";Fix="GUIDE";Msg="Fallo gráfico. Drivers u overlays."},
 @{Id="NET";Pattern="(?i)(error|failed|handshake).*connection|network.*failed";Fix="LIMITED";Msg="Error de red local."},
 @{Id="PERM";Pattern="(?i)(access is denied|permission.*denied)";Fix="AUTO";Msg="Permisos insuficientes."},
 @{Id="GTA";Pattern="(?i)gta.*not.*found|missing.*file";Fix="GUIDE";Msg="GTA V no inicializado."},
 @{Id="MODS";Pattern="(?i)mod.*conflict|dll.*conflict|asi.*conflict";Fix="AUTO";Msg="Mods/DLL conflictivos."}
)

# ---------------- SERVER / INTERNET ERRORS ----------------
$FiveMServerErrorCatalog = @(
 @{Code="TIMEOUT";Pattern="(?i)timed out|timeout.*server";Msg="Timeout. Internet o servidor."},
 @{Code="REFUSED";Pattern="(?i)connection refused";Msg="Servidor caído o IP incorrecta."},
 @{Code="BANNED";Pattern="(?i)banned|kicked";Msg="Restricción del servidor."}
)

# ---------------- NETWORK DIAGNOSTIC ----------------
function Test-NetworkQuality {
    Section "Diagnóstico de red (latencia / jitter / pérdida)"

    $target = "8.8.8.8"
    $pings = Test-Connection $target -Count 10 -ErrorAction SilentlyContinue

    if (-not $pings) {
        FAIL "No se pudo medir red. Posible bloqueo ICMP o fallo total de conexión."
        return
    }

    $latencies = $pings.ResponseTime
    $avg = [math]::Round(($latencies | Measure-Object -Average).Average,2)
    $min = ($latencies | Measure-Object -Minimum).Minimum
    $max = ($latencies | Measure-Object -Maximum).Maximum
    $jitter = [math]::Round($max - $min,2)
    $loss = 100 - (($latencies.Count / 10) * 100)

    OK "Latencia promedio: $avg ms"
    OK "Jitter aproximado: $jitter ms"
    OK "Pérdida de paquetes: $loss %"

    if ($avg -gt 120 -or $jitter -gt 50 -or $loss -gt 5) {
        FAIL "Calidad de red DEFICIENTE para FiveM"
        WARN "Este problema NO es del PC ni del programa"
        WARN "Causa probable: ISP, WiFi inestable o servidor"
    } else {
        OK "Calidad de red ACEPTABLE para FiveM"
    }

    $Global:Report.Network = @{
        Latency=$avg
        Jitter=$jitter
        Loss="$loss%"
    }
}

# ---------------- NAT DETECTION (INDIRECTA) ----------------
function Detect-NATType {
    Section "Detección de NAT"

    $ports = @(30120, 30110)
    $open = 0

    foreach ($p in $ports) {
        $test = Test-NetConnection -Port $p -ComputerName "google.com" -InformationLevel Quiet -ErrorAction SilentlyContinue
        if ($test) { $open++ }
    }

    if ($open -eq 0) {
        FAIL "NAT ESTRICTO detectado (puertos bloqueados)"
        WARN "FiveM puede fallar por esta causa"
        WARN "Solución:"
        Write-Host "- Activar UPnP"
        Write-Host "- Abrir puertos UDP/TCP 30120"
        Write-Host "- Evitar CG-NAT del proveedor"
        $Global:Report.NAT = "Estricto"
    } else {
        OK "NAT abierto o moderado"
        $Global:Report.NAT = "Abierto/Moderado"
    }
}

# ---------------- LOG ANALYSIS ----------------
function Detect-FiveMErrors {
    Section "Autodetección inteligente de errores FiveM"

    $logs = "$env:LOCALAPPDATA\FiveM\FiveM.app\logs"
    $detected = @()

    if (-not (Test-Path $logs)) {
        WARN "No se encontraron logs de FiveM"
        return
    }

    try {
        $currentLogs = Get-ChildItem $logs -Filter *.log -Recurse |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
            Sort LastWriteTime -Desc | Select -First 5

        foreach ($log in $currentLogs) {
            $content = Get-Content $log.FullName -ErrorAction SilentlyContinue

            foreach ($line in $content) {

                foreach ($e in $FiveMErrorCatalog) {
                    if ($line -match $e.Pattern) {
                        FAIL "Error detectado: $($e.Id)"
                        WARN $e.Msg
                        $detected += $e.Id

                        if ($e.Fix -eq "AUTO") {
                            WARN "Este error SE PUEDE reparar automáticamente"
                        }
                        elseif ($e.Fix -eq "LIMITED") {
                            WARN "Reparación limitada posible"
                        }
                        else {
                            WARN "Requiere acción del usuario"
                        }
                    }
                }

                foreach ($s in $FiveMServerErrorCatalog) {
                    if ($line -match $s.Pattern) {
                        FAIL "Error de servidor: $($s.Code)"
                        WARN $s.Msg
                        WARN "Este problema NO depende del PC"
                        $detected += $s.Code
                    }
                }
            }
        }

        if (-not $detected) {
            OK "No se detectaron errores críticos en logs recientes"
            $Global:Report.Errors = "Sin errores"
        } else {
            $Global:Report.Errors = ($detected | Sort-Object -Unique)
        }

    } catch {
        FAIL "Error analizando logs: $_"
    }
}

# ---------------- MASTER AUTO-DETECT ----------------
function AutoDetect-FiveM {
    Detect-FiveMErrors
    Test-NetworkQuality
    Detect-NATType
}


# ---------------- MODS ----------------
function Detect-ResidualMods {
    Section "Detección avanzada de mods (comparativo + ocultos)"

    if (-not $Global:Report.GTAPath) {
        FAIL "Ruta de GTA V no detectada"
        $Global:Report.Mods = "GTA no detectado"
        return
    }

    $findings = @()
    $severity = "Limpio"
    $recommendation = "OK"

    foreach ($gtaPath in $Global:Report.GTAPath) {

        Write-Host "Analizando: $gtaPath" -ForegroundColor Cyan

        # === Referencia temporal base (GTA5.exe vanilla) ===
        $gtaExe = Join-Path $gtaPath "GTA5.exe"
        if (-not (Test-Path $gtaExe)) { continue }
        $baseDate = (Get-Item $gtaExe).LastWriteTime

        # === Archivos críticos conocidos ===
        $criticalFiles = @(
            "dinput8.dll",
            "ScriptHookV.dll",
            "OpenIV.asi",
            "dxgi.dll",
            "d3d11.dll"
        )

        foreach ($file in $criticalFiles) {
            $full = Join-Path $gtaPath $file
            if (Test-Path $full) {

                # Firma digital (mods ocultos)
                $sig = Get-AuthenticodeSignature $full
                if ($sig.Status -ne "Valid") {
                    $findings += "DLL no firmada o sospechosa: $file"
                    $severity = "Crítico"
                }

                # Fecha posterior a instalación base
                if ((Get-Item $full).LastWriteTime -gt $baseDate) {
                    $findings += "Archivo crítico modificado tras instalación: $file"
                    $severity = "Crítico"
                }
            }
        }

        # === Archivos ASI ===
        Get-ChildItem $gtaPath -Filter *.asi -File -ErrorAction SilentlyContinue | ForEach-Object {
            $findings += "ASI detectado: $($_.Name)"
            $severity = "Crítico"
        }

        # === Carpetas típicas de mods ===
        foreach ($folder in @("mods","scripts","plugins","LSPDFR","reshade-shaders")) {
            if (Test-Path (Join-Path $gtaPath $folder)) {
                $findings += "Carpeta de mods detectada: $folder"
                $severity = "Crítico"
            }
        }

        # === update.rpf (criterio real sin falsos positivos) ===
        $updateRpf  = Join-Path $gtaPath "update\update.rpf"
        $modsFolder = Join-Path $gtaPath "mods"

        if (Test-Path $updateRpf) {
            $updateDate = (Get-Item $updateRpf).LastWriteTime
            $daysDiff  = (New-TimeSpan -Start $updateDate -End (Get-Date)).Days

            # Solo sospechoso si es reciente Y hay señales reales de mods
            if (
                ($daysDiff -le 7) -and
                (
                    (Test-Path $modsFolder) -or
                    ($severity -eq "Crítico")
                )
            ) {
                $findings += "update.rpf modificado recientemente ($daysDiff días)"
                if ($severity -ne "Crítico") { $severity = "Advertencia" }
                $recommendation = "Reinstalar solo update.rpf"
            }
        }
    }

    # === RESULTADO FINAL ===
    if ($findings.Count -gt 0) {
        FAIL "Se detectaron modificaciones en GTA V"

        $findings | Sort-Object -Unique | ForEach-Object {
            if ($severity -eq "Crítico") {
                FAIL $_
            } else {
                WARN $_
            }
        }

        if ($severity -eq "Crítico") {
            $recommendation = "Instalación limpia recomendada"
        }

        WARN "Diagnóstico: $severity"
        WARN "Acción sugerida: $recommendation"

        $Global:Report.Mods = @{
            Estado = $severity
            Recomendacion = $recommendation
            Hallazgos = ($findings | Sort-Object -Unique)
        }
    }
    else {
        OK "Instalación limpia (sin mods detectados)"
        $Global:Report.Mods = @{
            Estado = "Limpio"
            Recomendacion = "OK"
            Hallazgos = "Ninguno"
        }
    }
}


# ---------------- HARDWARE ADVICE (EXPANDIDO) ----------------
function Hardware-Recommendations {
    Section "Sugerencias por hardware"
    $rec=@()
    try {
        $ram=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory/1GB
        $gpu=(Get-WmiObject Win32_VideoController -ErrorAction Stop | Select -First 1).Name
        $cpu=(Get-WmiObject Win32_Processor -ErrorAction Stop | Select -First 1).Name
        $disk=(Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop).FreeSpace / 1GB

        if ($ram -lt 8){ WARN "RAM baja"; $rec+="Aumentar RAM / cerrar apps (https://fivem.net/docs/server-manual/setting-up-a-server-hardware-requirements)" }
        if ($gpu -match "Intel"){ WARN "GPU integrada"; $rec+="Bajar gráficos / usar GPU dedicada" }
        if ($cpu -match "i3|i5.*\d{4}"){ WARN "CPU antigua"; $rec+="Actualizar CPU si es posible" }
        if ($disk -lt 50){ WARN "Poco espacio en disco"; $rec+="Liberar espacio (mínimo 50GB recomendado)" }
        if (!$rec){ OK "Hardware adecuado"; $rec="OK" }
    } catch {
        FAIL "Error al analizar hardware: $_"
        $rec = "Error: $_"
    }
    $Global:Report.HardwareAdvice=$rec
}

# ---------------- EXPORT ----------------
function Export-Reports {
    Section "Exportando reportes"
    try {
        # Formato TXT legible (maneja Hashtables y ARRAYS correctamente)
        $txtContent = "Reporte FiveM - $($Global:Report.Timestamp)`n`n"

        $Global:Report.GetEnumerator() | ForEach-Object {

            $key = $_.Key
            $val = $_.Value

            # ===== ARRAY (GPU, Firewall, etc) =====
            if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string]) -and -not ($val -is [hashtable])) {

                $txtContent += "${key}:`n"

                foreach ($item in $val) {
                    if ($item -is [hashtable]) {
                        $item.GetEnumerator() | ForEach-Object {
                            $txtContent += "  - $($_.Key): $($_.Value)`n"
                        }
                        $txtContent += "`n"
                    }
                    else {
                        $txtContent += "  - $item`n"
                    }
                }
            }

            # ===== HASHTABLE (Mods, HardwareAdvice, Ports, etc) =====
            elseif ($val -is [hashtable]) {

                $txtContent += "${key}:`n"

                $val.GetEnumerator() | ForEach-Object {
                    if ($_.Value -is [System.Collections.IEnumerable] -and -not ($_.Value -is [string])) {
                        $txtContent += "  - $($_.Key):`n"
                        $_.Value | ForEach-Object {
                            $txtContent += "      * $_`n"
                        }
                    }
                    else {
                        $txtContent += "  - $($_.Key): $($_.Value)`n"
                    }
                }
            }

            # ===== VALOR SIMPLE =====
            else {
                $txtContent += "${key}: $val`n"
            }

            $txtContent += "`n"
        }

        $txtContent | Out-File $ReportTXT -Encoding UTF8 -ErrorAction Stop
        $Global:Report | ConvertTo-Json -Depth 6 | Out-File $ReportJSON -Encoding UTF8 -ErrorAction Stop

        OK "Reportes creados:"
        OK $ReportTXT
        OK $ReportJSON
    }
    catch {
        FAIL "Error al exportar reportes: $_"
    }
}

# ---------------- MENU ----------------
do {
    Header
    Write-Host "1) Diagnostico completo"
    Write-Host "2) Detectar GTA V"
    Write-Host "3) Limpiar cache FiveM"
    Write-Host "4) GPU / Drivers"
    Write-Host "5) RAM / Memoria virtual"
    Write-Host "6) Test puertos"
    Write-Host "7) Firewall"
    Write-Host "8) Overlays"
    Write-Host "9) Autodetectar errores FiveM"
    Write-Host "10) Detectar mods residuales"
    Write-Host "11) Sugerencias por hardware"
    Write-Host "12) Exportar reportes"
    Write-Host "0) Salir"
    $o=Read-Host "Opcion"

    switch ($o){
        "1"{
    $steps = 10
    $current = 0

    Detect-GTA
    $current++
    Progress $current $steps

    Clean-FiveMCache; Progress(++$current, $steps)
    Check-GPU; Progress(++$current, $steps)
    Check-RAM; Progress(++$current, $steps)
    Test-Ports; Progress(++$current, $steps)
    Check-Firewall; Progress(++$current, $steps)
    Overlay-Warning; Progress(++$current, $steps)
    Detect-FiveMErrors; Progress(++$current, $steps)
    Detect-ResidualMods; Progress(++$current, $steps)
    Hardware-Recommendations; Progress(++$current, $steps)

    Export-Reports
    Pause
}
        "2"{Detect-GTA;Pause}
        "3"{Clean-FiveMCache;Pause}
        "4"{Check-GPU;Pause}
        "5"{Check-RAM;Pause}
        "6"{Test-Ports;Pause}
        "7"{Check-Firewall;Pause}
        "8"{Overlay-Warning;Pause}
        "9"{Detect-FiveMErrors;Pause}
        "10"{Detect-ResidualMods;Pause}
        "11"{Hardware-Recommendations;Pause}
        "12"{Export-Reports;Pause}
        "0"{break}
        default{WARN "Opción inválida. Ingresa un número del 0 al 12.";Pause}
    }
} while ($true)