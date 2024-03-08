Dim proxyAgent 

set proxyAgent = GetScriptObject(WScript, "ProxyAgent.wsf", "ProxyAgent")

set proxyAgent.Script = WScript

proxyAgent.Initialize "."

' Remove the GuestProxyAgent service only,
' Do not delete the ProxyAgent main folder to avoid delete the local Logs and Keys folder
proxyAgent.UninstallProxyAgent "ServiceOnly"

Function GetScriptObject(WScript, scriptPath, componentId)
    Dim FSO, scriptDir
    Set FSO = CreateObject("Scripting.FileSystemObject")
    scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
    Set GetScriptObject = GetObject("script:" & FSO.BuildPath(scriptDir, scriptPath) & "#" & componentId)
End Function