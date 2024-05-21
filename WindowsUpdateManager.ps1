#windows update manager by zoic

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


try {

    Get-InstalledModule -Name PSWindowsUpdate -ErrorAction Stop | Out-Null

}
catch {
    $ProgressPreference = 'SilentlyContinue'
    Write-Host 'Installing Powershell Update Module...'
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null  
    Install-Module PSWindowsUpdate -SkipPublisherCheck -Force | Out-Null
    Set-ExecutionPolicy Unrestricted -Force
    Import-Module -Name PSWindowsUpdate -Force
    Clear-Host
}

function getAutoUpdates { 

    $settings = Get-WUSettings

    $autoUpdate = $settings.NoAutoUpdate
    return $autoUpdate
}

function getWUServer {

    $settings = Get-WUSettings

    $WUServer = $settings.WUServer
    return $WUServer

}

function getWUConnection {

    $settings = Get-WUSettings

    $WUCon = $settings.DoNotConnectToWindowsUpdateInternetLocations
    return $WUCon

}

function getWUService {
    $regkey = Get-ItemPropertyValue 'registry::HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' -Name 'Start' 
    $uso = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq 'UsoSvc' }

    if ($regkey -eq '2' -and $uso.State -eq 'Running') {
        return 'WU Service Running and Enabled'

    }
    elseif ($regkey -eq '2' -and $uso.State -ne 'Running') {
        return 'WU Service needs restart'

    }
    else {
        return 'WU Service Disabled'

    } 
}

function getDOService {
    #get service
    $service = (Get-Service -Name DoSvc).Status
    if ($service -eq 'Running') {
        return 'Delivery Optimization Running'
    }
    else {
        return 'Delivery Optimization Stopped'
    }
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()  
    
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Update Manager'
$form.Size = New-Object System.Drawing.Size(420, 420)
$form.StartPosition = 'CenterScreen'
$form.BackColor = 'Black'

$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Location = New-Object System.Drawing.Size(-4, 15)
$TabControl.Size = New-Object System.Drawing.Size(480, 460) 
$TabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


$TabPage1 = New-Object System.Windows.Forms.TabPage
$TabPage1.Text = 'Update Configuration'
$TabPage1.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


$TabPage2 = New-Object System.Windows.Forms.TabPage
$TabPage2.Text = 'Update Manager'
$TabPage2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


$TabControl.Controls.Add($TabPage1)
$TabControl.Controls.Add($TabPage2)
$Form.Controls.Add($TabControl)

$label1 = New-Object System.Windows.Forms.Label
$label1.Location = New-Object System.Drawing.Point(10, 10)
$label1.Size = New-Object System.Drawing.Size(150, 25)
$label1.Text = 'Enable Options:'
$label1.ForeColor = 'White'
$label1.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
$form.Controls.Add($label1)
$TabPage1.Controls.Add($label1)
      
$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(200, 10)  
$label2.Size = New-Object System.Drawing.Size(150, 25)
$label2.Text = 'Disable Options:'
$label2.ForeColor = 'White'
$label2.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
$form.Controls.Add($label2)
$TabPage1.Controls.Add($label2)


$btn1 = New-Object Windows.Forms.Button
$btn1.Text = 'Disable Updates'
$btn1.Location = New-Object Drawing.Point(200, 40)
$btn1.Size = New-Object Drawing.Size(130, 35)
$btn1.Add_Click({
    
        Write-Host '-----------------DISABLING UPDATES-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /t REG_DWORD /d '0' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '4' /f
        gpupdate /force
    
        Write-Host '-----------------UPDATES DISABLED-----------------' 


    })
$form.Controls.Add($btn1)
$btn1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn1.ForeColor = [System.Drawing.Color]::White
$btn1.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn1.FlatAppearance.BorderSize = 0
$btn1.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn1.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn1)


$btn2 = New-Object Windows.Forms.Button
$btn2.Text = 'Pause Updates'
$btn2.Location = New-Object Drawing.Point(10, 80)
$btn2.Size = New-Object Drawing.Size(130, 35)
$btn2.Add_Click({
        Write-Host '-----------------PAUSING UPDATES-----------------'



        $form2 = New-Object System.Windows.Forms.Form
        $form2.Text = 'Pause Updates'
        $form2.Size = New-Object System.Drawing.Size(300, 150)
        $form2.StartPosition = 'CenterScreen'
        $form2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(280, 20)
        $label.Text = 'Enter the number of days to pause updates:'
        $label.ForeColor = 'White'
        $form2.Controls.Add($label)


        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 50)
        $textBox.Size = New-Object System.Drawing.Size(100, 20)
        #prevent letters from being typed
        $textBox.Add_KeyPress({
                param($sender, $e)

                # Check if the key pressed is not a digit or control key
                if (-not [char]::IsDigit($e.KeyChar) -and -not [char]::IsControl($e.KeyChar)) {
                    # If it's not, handle the event by setting Handled to true
                    $e.Handled = $true
                }
            })
        $form2.Controls.Add($textBox)


        $button = New-Object System.Windows.Forms.Button
        $button.Location = New-Object System.Drawing.Point(120, 80)
        $button.Size = New-Object System.Drawing.Size(75, 23)
        $button.Text = 'OK'
        $button.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $button.FlatAppearance.BorderSize = 0
        $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
        $button.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
        $button.Add_Click({
    
                $days = [int]$textBox.Text

                $form2.Close()

                if ($days -gt 500) {
                    Write-Host 'Days greater than 500...Pausing for MAX [500 days]'
                    $days = 500
                }

                $pause = (Get-Date).AddDays($days) 
                $today = Get-Date
                $today = $today.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' )
                $pause = $pause.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' ) 
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $today -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $today -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $today -Force
                Write-Host "-----------------UPDATES PAUSED FOR $DAYS DAYS-----------------"    
    
            })
        $form2.Controls.Add($button)


        $form2.ShowDialog()






    })
$form.Controls.Add($btn2)
$btn2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn2.ForeColor = [System.Drawing.Color]::White
$btn2.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn2.FlatAppearance.BorderSize = 0
$btn2.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn2.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn2)

$btn3 = New-Object Windows.Forms.Button
$btn3.Text = 'Disable Drivers in Update'
$btn3.Location = New-Object Drawing.Point(200, 80)
$btn3.Size = New-Object Drawing.Size(130, 35)
$btn3.Add_Click({
        Write-Host '-----------------DISABLING DRIVERS IN WINDOWS UPDATE-----------------' 
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
        gpupdate /force
    
        Write-Host '-----------------DRIVERS IN UPDATES DISABLED-----------------' 
    })
$form.Controls.Add($btn3)
$btn3.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn3.ForeColor = [System.Drawing.Color]::White
$btn3.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn3.FlatAppearance.BorderSize = 0
$btn3.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn3.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn3)

$btn4 = New-Object Windows.Forms.Button
$btn4.Text = 'Disable Auto Driver Searching'
$btn4.Location = New-Object Drawing.Point(200, 160)
$btn4.Size = New-Object Drawing.Size(130, 35)
$btn4.Add_Click({
        Write-Host '-----------------DISABLING DRIVER SEARCHING-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '0' /f
        Write-Host '-----------------DRIVER SEARCHING DISABLED-----------------'
    })
$form.Controls.Add($btn4)
$btn4.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn4.ForeColor = [System.Drawing.Color]::White
$btn4.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn4.FlatAppearance.BorderSize = 0
$btn4.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn4.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn4)


$btn5 = New-Object Windows.Forms.Button
$btn5.Text = 'Disable Optional Updates'
$btn5.Location = New-Object Drawing.Point(200, 120)
$btn5.Size = New-Object Drawing.Size(130, 35)
$btn5.Add_Click({
        Write-Host '-----------------DISABLING OPTIONAL UPDATES (W11 ONLY)-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
        gpupdate /force
        Write-Host '-----------------OPTIONAL UPDATES DISABLED-----------------'
    })
$form.Controls.Add($btn5)
$btn5.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn5.ForeColor = [System.Drawing.Color]::White
$btn5.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn5.FlatAppearance.BorderSize = 0
$btn5.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn5.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn5)


$btn6 = New-Object Windows.Forms.Button
$btn6.Text = 'Enable Updates'
$btn6.Location = New-Object Drawing.Point(10, 40)
$btn6.Size = New-Object Drawing.Size(130, 35)
$btn6.Add_Click({
        Write-Host '-----------------ENABLING UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        #remove pause values
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseUpdatesExpiryTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseFeatureUpdatesEndTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseFeatureUpdatesStartTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseQualityUpdatesEndTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseQualityUpdatesStartTime' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'PauseUpdatesStartTime' /f >$null 2>&1
        gpupdate /force
        Write-Host '-----------------UPDATES ENABLED-----------------'
    })
$form.Controls.Add($btn6)
$btn6.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn6.ForeColor = [System.Drawing.Color]::White
$btn6.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn6.FlatAppearance.BorderSize = 0
$btn6.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn6.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn6)

$btn7 = New-Object Windows.Forms.Button
$btn7.Text = 'Disable Update Restart Notifications'
$btn7.Location = New-Object Drawing.Point(200, 200)
$btn7.Size = New-Object Drawing.Size(130, 35)
$btn7.Add_Click({
        Write-Host '-----------------DISABLING NOTIFICATIONS-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAUShutdownOption' /t REG_DWORD /d '1' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'RestartNotificationsAllowed2' /t REG_DWORD /d '0' /f
        gpupdate /force
        Write-Host '-----------------NOTIFICATIONS DISABLED-----------------'  
    })
$form.Controls.Add($btn7)
$btn7.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn7.ForeColor = [System.Drawing.Color]::White
$btn7.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn7.FlatAppearance.BorderSize = 0
$btn7.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn7.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn7)


$btn8 = New-Object Windows.Forms.Button
$btn8.Text = 'Defer Feature and Quality Updates'
$btn8.Location = New-Object Drawing.Point(200, 240)
$btn8.Size = New-Object Drawing.Size(130, 35)
$btn8.Add_Click({
        Write-Host '-----------------DEFERING FEATURE AND QUALITY UPDATES FOR [MAX] DAYS-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '365' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '30' /f >$null
        gpupdate /force
        Write-Host '-----------------DEFERED FEATURE UPDATES[365d] QUALITY UPDATES[30d]-----------------'  
    })
$form.Controls.Add($btn8)
$btn8.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn8.ForeColor = [System.Drawing.Color]::White
$btn8.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn8.FlatAppearance.BorderSize = 0
$btn8.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn8.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn8)


$btn9 = New-Object Windows.Forms.Button
$btn9.Text = 'Disable Delivery Optimization'
$btn9.Location = New-Object Drawing.Point(200, 280)
$btn9.Size = New-Object Drawing.Size(130, 35)
$btn9.Add_Click({
        Write-Host '-----------------DISABLING DELIVERY OPTIMIZATION-----------------'
        Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue 
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '4' /f
        Reg.exe add 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t REG_DWORD /d '0' /f
        Write-Host '-----------------DISABLED DELIVERY OPTIMIZATION-----------------'  
    })
$form.Controls.Add($btn9)
$btn9.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn9.ForeColor = [System.Drawing.Color]::White
$btn9.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn9.FlatAppearance.BorderSize = 0
$btn9.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn9.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn9)


$btn10 = New-Object Windows.Forms.Button
$btn10.Text = 'Enable Optional Updates'
$btn10.Location = New-Object Drawing.Point(10, 120)
$btn10.Size = New-Object Drawing.Size(130, 35)
$btn10.Add_Click({
        Write-Host '-----------------ENABLING OPTIONAL UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /f >$null
        gpupdate /force
        Write-Host '-----------------OPTIONAL UPDATES ENABLED-----------------'  
    })
$form.Controls.Add($btn10)
$btn10.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn10.ForeColor = [System.Drawing.Color]::White
$btn10.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn10.FlatAppearance.BorderSize = 0
$btn10.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn10.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn10)


$btn11 = New-Object Windows.Forms.Button
$btn11.Text = 'Enable Auto Driver Searching'
$btn11.Location = New-Object Drawing.Point(10, 160)
$btn11.Size = New-Object Drawing.Size(130, 35)
$btn11.Add_Click({
        Write-Host '-----------------ENABLING AUTO DRIVER SEARCHING-----------------'
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '1' /f
        Write-Host '-----------------AUTO DRIVER SEARCHING ENABLED-----------------'  
    })
$form.Controls.Add($btn11)
$btn11.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn11.ForeColor = [System.Drawing.Color]::White
$btn11.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn11.FlatAppearance.BorderSize = 0
$btn11.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn11.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn11)



$btn12 = New-Object Windows.Forms.Button
$btn12.Text = 'Enable Update Restart Notifications'
$btn12.Location = New-Object Drawing.Point(10, 200)
$btn12.Size = New-Object Drawing.Size(130, 35)
$btn12.Add_Click({
        Write-Host '-----------------ENABLING UPDATE RESTART NOTIFICATIONS-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAUShutdownOption' /f
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'RestartNotificationsAllowed2' /t REG_DWORD /d '1' /f
        gpupdate /force
        Write-Host '-----------------UPDATE RESTART NOTIFICATIONS ENABLED-----------------'  
    })
$form.Controls.Add($btn12)
$btn12.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn12.ForeColor = [System.Drawing.Color]::White
$btn12.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn12.FlatAppearance.BorderSize = 0
$btn12.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn12.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn12)


$btn13 = New-Object Windows.Forms.Button
$btn13.Text = 'Allow Feature and Quality Updates'
$btn13.Location = New-Object Drawing.Point(10, 240)
$btn13.Size = New-Object Drawing.Size(130, 35)
$btn13.Add_Click({
        Write-Host '-----------------ALLOWING FEATURE AND QUALITY UPDATES-----------------'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /f 
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /f 
        gpupdate /force
        Write-Host '-----------------FEATURE AND QUALITY UPDATES ENABLED-----------------'  
    })
$form.Controls.Add($btn13)
$btn13.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn13.ForeColor = [System.Drawing.Color]::White
$btn13.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn13.FlatAppearance.BorderSize = 0
$btn13.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn13.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn13)


$btn14 = New-Object Windows.Forms.Button
$btn14.Text = 'Enable Delivery Optimization'
$btn14.Location = New-Object Drawing.Point(10, 280)
$btn14.Size = New-Object Drawing.Size(130, 35)
$btn14.Add_Click({
        Write-Host '-----------------ENABLING DELIVERY OPTIMIZATION-----------------'
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'DelayedAutostart' /t REG_DWORD /d '1' /f
        Reg.exe delete 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /f
        Start-Service -Name DoSvc -ErrorAction SilentlyContinue 
        Write-Host '-----------------DELIVERY OPTIMIZATION ENABLED-----------------'  
    })
$form.Controls.Add($btn14)
$btn14.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btn14.ForeColor = [System.Drawing.Color]::White
$btn14.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btn14.FlatAppearance.BorderSize = 0
$btn14.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$btn14.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage1.Controls.Add($btn14)

#TAB 2

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.Size = New-Object System.Drawing.Size(280, 20)
$label.Text = 'Update Dependencies:'
$boldFont = New-Object System.Drawing.Font($label.Font, [System.Drawing.FontStyle]::Bold)
$label.Font = $boldFont
$label.ForeColor = 'White'
$form.Controls.Add($label)
$TabPage2.Controls.Add($label)

$Global:label2 = New-Object System.Windows.Forms.Label
$Global:label3 = New-Object System.Windows.Forms.Label
$Global:label4 = New-Object System.Windows.Forms.Label
$Global:label5 = New-Object System.Windows.Forms.Label
$Global:label6 = New-Object System.Windows.Forms.Label
function getDependencies {
    
    $label2.Location = New-Object System.Drawing.Point(15, 40)
    $label2.Size = New-Object System.Drawing.Size(180, 20)
    $label2.ForeColor = 'White'
    if (getAutoUpdates -eq 1) { $label2.Text = 'Auto Updates Disabled' }
    else { $label2.Text = 'Auto Updates Enabled' }
    $form.Controls.Add($label2)
    $TabPage2.Controls.Add($label2)

    $server = getWUServer
    
    $label3.Location = New-Object System.Drawing.Point(15, 60)
    $label3.Size = New-Object System.Drawing.Size(200, 30)
    $label3.ForeColor = 'White'
    if ($server -eq $null) {
        $server = 'Default'
        $label3.Size = New-Object System.Drawing.Size(200, 20)
    }
    $label3.Text = "Windows Update Server: $server"
    $form.Controls.Add($label3)
    $TabPage2.Controls.Add($label3)

    
    if ($server -ne 'Default') {
        $label4.Location = New-Object System.Drawing.Point(15, 90)
    }
    else {
        $label4.Location = New-Object System.Drawing.Point(15, 80)
    }
    $label4.Size = New-Object System.Drawing.Size(180, 20)
    $label4.ForeColor = 'White'
    if (getWUConnection -eq 1) { $label4.Text = 'Connect to WU Server Disabled' }
    else { $label4.Text = 'Connect to WU Server Enabled' }
    $form.Controls.Add($label4)
    $TabPage2.Controls.Add($label4)

    
    if ($server -ne 'Default') {
        $label5.Location = New-Object System.Drawing.Point(15, 110)
    }
    else {
        $label5.Location = New-Object System.Drawing.Point(15, 100)
    }
    $label5.Size = New-Object System.Drawing.Size(180, 20)
    $label5.ForeColor = 'White'
    $text = getWUService
    $label5.Text = $text
    $form.Controls.Add($label5)
    $TabPage2.Controls.Add($label5)

    
    if ($server -ne 'Default') {
        $label6.Location = New-Object System.Drawing.Point(15, 130)
    }
    else {
        $label6.Location = New-Object System.Drawing.Point(15, 120)
    }
    $label6.Size = New-Object System.Drawing.Size(180, 20)
    $label6.ForeColor = 'White'
    $text = getDOService
    $label6.Text = $text
    $form.Controls.Add($label6)
    $TabPage2.Controls.Add($label6)
}
getDependencies

function refresh {
    $label2.Text = ''
    $label3.Text = ''
    $label4.Text = ''
    $label5.Text = ''
    $label6.Text = ''
    getDependencies 
}
$refreshBttn = New-Object Windows.Forms.Button
$refreshBttn.Text = 'Refresh'
$refreshBttn.Location = New-Object Drawing.Point(10, 155)
$refreshBttn.Size = New-Object Drawing.Size(70, 20)
$refreshBttn.Add_Click({
        refresh
    })
$form.Controls.Add($refreshBttn)
$refreshBttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$refreshBttn.ForeColor = [System.Drawing.Color]::White
$refreshBttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$refreshBttn.FlatAppearance.BorderSize = 0
$refreshBttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$refreshBttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($refreshBttn)



$clearDOcache = New-Object Windows.Forms.Button
$clearDOcache.Text = 'Clear Delivery Optimization Cache'
$clearDOcache.Location = New-Object Drawing.Point(250, 40)
$clearDOcache.Size = New-Object Drawing.Size(120, 35)
$clearDOcache.Add_Click({
        #clear delivery optmization cache
        Write-Host 'Clearing Delivery Optimization Cache'
        try {
            #will error if dosvc is disabled 
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
        }
        catch {
            #delete cache manually
            Remove-Item -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*' -Force -Recurse
        }
        Write-Host 'Cleared'
    })
$form.Controls.Add($clearDOcache)
$clearDOcache.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$clearDOcache.ForeColor = [System.Drawing.Color]::White
$clearDOcache.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearDOcache.FlatAppearance.BorderSize = 0
$clearDOcache.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$clearDOcache.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($clearDOcache)


$clearUpdateCache = New-Object Windows.Forms.Button
$clearUpdateCache.Text = 'Clear Windows Update Cache'
$clearUpdateCache.Location = New-Object Drawing.Point(250, 90)
$clearUpdateCache.Size = New-Object Drawing.Size(120, 35)
$clearUpdateCache.Add_Click({
        #clear windows update cache
        Write-Host 'Clearing Windows Update Cache'
        $wusvc = (Get-Service -Name wuauserv).Status
        $bits = (Get-Service -Name BITS).Status
        if (!($wusvc -eq 'Stopped')) {
            Stop-Service -Name wuauserv -Force
        }
        if (!($bits -eq 'Stopped')) {
            Stop-Service -Name BITS -Force
        }
        Remove-Item -Path 'C:\Windows\SoftwareDistribution\*' -Recurse -Force 
        #start the services again if they were running 
        if (!($wusvc -eq 'Stopped')) {
            Start-Service -Name wuauserv 
        }
        if (!($bits -eq 'Stopped')) {
            Start-Service -Name BITS 
        }
        Write-Host 'Cleared'
    })
$form.Controls.Add($clearUpdateCache)
$clearUpdateCache.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$clearUpdateCache.ForeColor = [System.Drawing.Color]::White
$clearUpdateCache.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$clearUpdateCache.FlatAppearance.BorderSize = 0
$clearUpdateCache.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$clearUpdateCache.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($clearUpdateCache)


$checkingUpdates = New-Object System.Windows.Forms.Label
$checkingUpdates.Location = New-Object System.Drawing.Point(10, 200)
$checkingUpdates.Size = New-Object System.Drawing.Size(180, 20)
$checkingUpdates.ForeColor = 'White'
$checkingUpdates.BackColor = 'Black'
$checkingUpdates.Text = 'Checking For Updates...' 
$checkingUpdates.Visible = $false
$TabPage2.Controls.Add($checkingUpdates)

$checkingUpdatesDriver = New-Object System.Windows.Forms.Label
$checkingUpdatesDriver.Location = New-Object System.Drawing.Point(10, 200)
$checkingUpdatesDriver.Size = New-Object System.Drawing.Size(180, 20)
$checkingUpdatesDriver.ForeColor = 'White'
$checkingUpdatesDriver.BackColor = 'Black'
$checkingUpdatesDriver.Text = 'Checking For Driver Updates...' 
$checkingUpdatesDriver.Visible = $false
$TabPage2.Controls.Add($checkingUpdatesDriver)

$noDriverUpdates = New-Object System.Windows.Forms.Label
$noDriverUpdates.Location = New-Object System.Drawing.Point(10, 200)
$noDriverUpdates.Size = New-Object System.Drawing.Size(180, 20)
$noDriverUpdates.ForeColor = 'White'
$noDriverUpdates.BackColor = 'Black'
$noDriverUpdates.Text = 'No Driver Updates Found...' 
$noDriverUpdates.Visible = $false
$TabPage2.Controls.Add($noDriverUpdates)

$noUpdates = New-Object System.Windows.Forms.Label
$noUpdates.Location = New-Object System.Drawing.Point(10, 200)
$noUpdates.Size = New-Object System.Drawing.Size(180, 20)
$noUpdates.ForeColor = 'White'
$noUpdates.BackColor = 'Black'
$noUpdates.Text = 'No Updates Found...' 
$noUpdates.Visible = $false
$TabPage2.Controls.Add($noUpdates)

$checkedListBox = New-Object System.Windows.Forms.CheckedListBox
$checkedListBox.Location = New-Object System.Drawing.Point(7, 190)
$checkedListBox.Size = New-Object System.Drawing.Size(390, 120)
$checkedListBox.BackColor = 'Black'
$checkedListBox.ForeColor = 'White'
$checkedListBox.ScrollAlwaysVisible = $false
$TabPage2.Controls.Add($checkedListBox)


$checkForUpdate = {
    $noDriverUpdates.Visible = $false
    $noUpdates.Visible = $false
    $showOnlyDriver.Checked = $false

    $checkingUpdates.Visible = $true
    $form.Refresh()
    $checkedListBox.Items.Clear()
    $Global:updates = Get-WindowsUpdate
    if (!$updates) {
        $noUpdates.Visible = $true
    }
    else {
        foreach ($update in $updates) {
            $checkedListBox.Items.Add($update.Title, $false)
        }
        
        if ($checkedListBox.Items.Count -gt 7) {
            $checkedListBox.ScrollAlwaysVisible = $true
        }
    }
    
    $checkingUpdates.Visible = $false
}

$checkUpdate = New-Object Windows.Forms.Button
$checkUpdate.Text = 'Check for Updates'
$checkUpdate.Location = New-Object Drawing.Point(10, 310)
$checkUpdate.Size = New-Object Drawing.Size(120, 35)
$checkUpdate.Add_Click({
        &$checkForUpdate
    })
$form.Controls.Add($checkUpdate)
$checkUpdate.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$checkUpdate.ForeColor = [System.Drawing.Color]::White
$checkUpdate.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$checkUpdate.FlatAppearance.BorderSize = 0
$checkUpdate.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$checkUpdate.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($checkUpdate)


$installSelectedUpdate = {
    Write-Host 'Installing Selected Updates'
    foreach ($selectedUpdate in $checkedListBox.CheckedItems.GetEnumerator()) {
        #get kb id
        if ($updates) {
            foreach ($update in $updates) {
                if ($update.Title -eq $selectedUpdate) {
                    $KBID = $update.KB
                }
            }
        }
        else {
            #driver updates
            foreach ($driverUpdate in $driverUpdates) {
                if ($driverUpdate.Title -eq $selectedUpdate) {
                    $KBID = $driverUpdate.KB
                }
            }
        }

        Write-Host 'Installing', $selectedUpdate
        Install-WindowsUpdate -KBArticleID $KBID -AcceptAll -IgnoreReboot
    }
    Write-Host 'Restart to Finish Updates'
}

$installSelected = New-Object Windows.Forms.Button
$installSelected.Text = 'Install Selected Updates'
$installSelected.Location = New-Object Drawing.Point(140, 310)
$installSelected.Size = New-Object Drawing.Size(120, 35)
$installSelected.Add_Click({
        &$installSelectedUpdate
    })
$form.Controls.Add($installSelected)
$installSelected.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$installSelected.ForeColor = [System.Drawing.Color]::White
$installSelected.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$installSelected.FlatAppearance.BorderSize = 0
$installSelected.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$installSelected.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($installSelected)


$installAllUpdates = {
    #check update server
    $server = getWUServer
    $serverConnect = getWUConnection
    if ($server -ne $null -or $serverConnect) {
        #enable connection so that get-windowsupdate works
        Write-host 'Connect to Windows Update Location Disabled...'
        Write-Host 'Enabling Connection'
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f >$null 2>&1
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f >$null 2>&1
    }
    
    Write-Host 'Installing All Updates'
    $allupdates = Get-WindowsUpdate 
    if (!$allupdates) {
        Write-Host 'No Updates Found'
    }
    else {
        foreach ($update in $allupdates) {
            Write-Host "Installing $($update.Title)" 
            Install-WindowsUpdate -KBArticleID $update.KB -AcceptAll -IgnoreReboot
        }
        if ($server -ne $null -or $serverConnect) { 
            Write-Host 'Disabling Windows Update Location Connectivity'
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f 
        }
        
        Write-Host 'Restart To Finish Updates'
        
    }
}

$installALL = New-Object Windows.Forms.Button
$installALL.Text = 'Install All Updates'
$installALL.Location = New-Object Drawing.Point(270, 310)
$installALL.Size = New-Object Drawing.Size(120, 35)
$installALL.Add_Click({
        &$installAllUpdates
    })
$form.Controls.Add($installALL)
$installALL.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$installALL.ForeColor = [System.Drawing.Color]::White
$installALL.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$installALL.FlatAppearance.BorderSize = 0
$installALL.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
$installALL.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$TabPage2.Controls.Add($installALL)


$showDriver = {
    if ($showOnlyDriver.Checked) {
        $noDriverUpdates.Visible = $false
        $noUpdates.Visible = $false
        
        $checkedListBox.Items.Clear()
        $checkingUpdatesDriver.Visible = $true
        $form.Refresh()

        $Global:driverUpdates = Get-WindowsUpdate -UpdateType Driver
        if (!$driverUpdates) {
            $noDriverUpdates.Visible = $true
        } 
        foreach ($driverUpdate in $driverUpdates) {
            $checkedListBox.Items.Add($driverUpdate.Title, $false)
        }
        #show scroll bar if there is more than 7 updates
        if ($checkedListBox.Items.Count -gt 7) {
            $checkedListBox.ScrollAlwaysVisible = $true
        }

        $checkingUpdatesDriver.Visible = $false
    }
    else {
        $noDriverUpdates.Visible = $false
        if ($updates) {
            $checkedListBox.Items.Clear()
            foreach ($update in $updates) {
                $checkedListBox.Items.Add($update.Title, $false)
            }
        }
    }
}

$showOnlyDriver = New-Object System.Windows.Forms.CheckBox
$showOnlyDriver.Location = New-Object System.Drawing.Point(250, 170)
$showOnlyDriver.Size = New-Object System.Drawing.Size(170, 20)
$showOnlyDriver.ForeColor = 'White'
$showOnlyDriver.Text = 'Show Only Driver Updates'
$showOnlyDriver.add_CheckedChanged($showDriver)
$TabPage2.Controls.Add($showOnlyDriver)


$Form.Add_Shown({ $Form.Activate() })
$form.ShowDialog() | Out-Null
