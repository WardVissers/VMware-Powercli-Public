# General
$viserver = read-host "What is name of the vCenter"
$viuser = read-host "What is name user connect to connect to vCenter"
$vipassword = read-host "What is password for the user"

# Set-PowerCLIConfiguration -InvalidCertificateAction Ignore
connect-viserver $viserver -user $viuser -password $vipassword

# NFS
$NFSServer = "XXX.XXX.XXX.XXX"
$NFSVersion = "4.1"
$NFSShare1 = "VMware_NFS_Lun01"
$NFSShare1Path = "/volume1/VMware_NFS_Lun01"
$NFSShare2 = "VMware_NFS_Lun02"
$NFSShare2Path = "/volume1/VMware_NFS_Lun02"
# Get Cluster
$cluster=Get-Cluster  | Sort-Object -Property Name | Out-GridView -OutputMode Single -Title "Select Source Cluster"
# Get VMhosts
$vmhosts = Get-Cluster $cluster | Get-VMhost
# Add to Each Host in the Cluster the NFS Lun's
foreach ($vmhost in $vmhosts) {
    New-Datastore -Nfs -FileSystemVersion $NFSVersion -vmhost $vmhost -Name $NFSShare1 -Path $NFSShare1Path -NfsHost $NFSServer  #-Kerberos
    New-Datastore -Nfs -FileSystemVersion $NFSVersion -vmhost $vmhost -Name $NFSShare2 -Path $NFSShare2Path -NfsHost $NFSServer  #-Kerberos
}
# Disconnect vCenter
Disconnect-VIServer * -Confirm:$false