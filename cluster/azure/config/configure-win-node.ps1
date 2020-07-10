[CmdletBinding()]
param(
  $KubeletPort=10250
)

echo "open kubelet port 10250"
netsh advfirewall firewall add rule name="Kubelet port $KubeletPort" dir=in action=allow protocol=TCP localport=$KubeletPort
echo "Check and install required Windows features"
Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN
if ((Get-WindowsFeature RemoteAccess).InstallState -notlike 'installed'){
  echo "installing feature 'RemoteAccess'"
  Install-WindowsFeature RemoteAccess
}
if ((Get-WindowsFeature Routing).InstallState -notlike 'installed'){
  echo "installing feature 'Routing'"
  Install-WindowsFeature Routing
}
if ((Get-WindowsFeature DirectAccess-VPN).InstallState -notlike 'installed'){
  echo "installing feature 'DirectAccess-VPN'"
  Install-WindowsFeature DirectAccess-VPN
}
Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN
Set-Service -Name RemoteAccess -ComputerName . -StartupType "Automatic"
Get-Service RemoteAccess | select -Property name,status,starttype
echo "Rebooting node ..."
Restart-Computer
