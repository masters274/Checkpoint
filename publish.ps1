
$modulePath = "$PSScriptRoot\CheckPoint"

$requiredModules = @('core', 'Posh-SSH')

foreach ($mod in $requiredModules) {
    $module = Get-Module -Name $mod -ListAvailable
    if ($module -eq $null) {
        Install-Module -Name $mod -Force -Scope CurrentUser
    }
}

Publish-Module -Path $modulePath -NuGetApiKey $Env:APIKEY