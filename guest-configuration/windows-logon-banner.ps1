Install-Module 'PSDscResources'

Configuration windows-logon-banner
{
    param
    (
        [String]
        $BannerTitle,

        [String]
        $BannerText
    )

    Import-DscResource -ModuleName 'PSDscResources'

    Node localhost {
        Registry 'Ensure Windows logon banner title is set correctly'
        {
            Ensure = 'Present'
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "legalnoticecaption"
            ValueData = $BannerTitle
            ValueType = "String"
        }

        Registry 'Ensure Windows logon banner text is set correctly'
        {
            Ensure = 'Present'
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "legalnoticetext"
            ValueData = $BannerText
            ValueType = "String"
        }
    }
}

windows-logon-banner -BannerTitle "title" -BannerText "text"

