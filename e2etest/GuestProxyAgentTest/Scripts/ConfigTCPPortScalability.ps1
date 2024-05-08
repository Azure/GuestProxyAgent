# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

Set-NetTCPSetting -SettingName "InternetCustom" -DynamicPortRangeStartPort 5000 -DynamicPortRangeNumberOfPorts 19475 -AutoReusePortRangeStartPort 22000 -AutoReusePortRangeNumberOfPorts 43536
Set-NetTCPSetting -SettingName "DatacenterCustom" -DynamicPortRangeStartPort 5000 -DynamicPortRangeNumberOfPorts 19475 -AutoReusePortRangeStartPort 22000 -AutoReusePortRangeNumberOfPorts 43536
Set-NetTCPSetting -SettingName "Compat" -DynamicPortRangeStartPort 5000 -DynamicPortRangeNumberOfPorts 19475 -AutoReusePortRangeStartPort 22000 -AutoReusePortRangeNumberOfPorts 43536
Set-NetTCPSetting -SettingName "Datacenter" -DynamicPortRangeStartPort 5000 -DynamicPortRangeNumberOfPorts 19475 -AutoReusePortRangeStartPort 22000 -AutoReusePortRangeNumberOfPorts 43536
Set-NetTCPSetting -SettingName "Internet" -DynamicPortRangeStartPort 5000 -DynamicPortRangeNumberOfPorts 19475 -AutoReusePortRangeStartPort 22000 -AutoReusePortRangeNumberOfPorts 43536