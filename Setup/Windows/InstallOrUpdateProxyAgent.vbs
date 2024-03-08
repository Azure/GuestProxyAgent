Dim proxyAgent 

set proxyAgent = GetScriptObject(WScript, "ProxyAgent.wsf", "ProxyAgent")

set proxyAgent.Script = WScript

proxyAgent.Initialize "."
proxyAgent.ConfigureProxyAgent()

proxyAgent.PostInstallation()

Function GetScriptObject(WScript, scriptPath, componentId)
    Dim FSO, scriptDir
    Set FSO = CreateObject("Scripting.FileSystemObject")
    scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
    Set GetScriptObject = GetObject("script:" & FSO.BuildPath(scriptDir, scriptPath) & "#" & componentId)
End Function
