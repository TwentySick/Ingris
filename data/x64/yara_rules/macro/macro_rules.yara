rule VBA_Autorun {
    strings:
        $a = "AutoExec" nocase fullword
        $b = "AutoOpen" nocase fullword
        $c = "DocumentOpen" nocase fullword
        $d = "AutoExit" nocase fullword
        $e = "AutoClose" nocase fullword
        $f = "Document_Close" nocase fullword
        $g = "DocumentBeforeClose" nocase fullword
        $h = "Document_Open" nocase fullword
        $i = "Document_BeforeClose" nocase fullword
        $j = "Auto_Open" nocase fullword
        $k = "Workbook_Open" nocase fullword
        $l = "Workbook_Activate" nocase fullword
        $m = "Auto_Close" nocase fullword
        $n = "Workbook_Close" nocase fullword
    condition:
        any of ($*)
}

rule VBA_Object {
    strings:
        $a = "CreateObject" nocase fullword
        $b = "GetObject" nocase fullword
    condition:
        any of ($*)
}

rule VBA_Declare {
    strings:
        $a = "Declare" nocase fullword
    condition:
        any of ($*)
}

rule VBA_CallByName {
    strings:
        $a = "CallByName" nocase fullword
    condition:
        any of ($*)
}

rule VBA_Shell {
    strings:
        $a = ".Run" nocase
        $b = "Shell" nocase fullword
    condition:
        any of ($*)
}
