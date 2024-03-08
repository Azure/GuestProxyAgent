Option Explicit

Const TemporaryFolder = 2
Const ForReading = 1

' execute the given command, collecting the results to an object
Function ExecuteWithResults (strCommand)

    Dim FSO, WshShell
    Dim outFile, errFile 
    Dim runCmd, oResults

    Set WshShell = CreateObject("WScript.Shell")
    Set FSO = CreateObject("Scripting.FileSystemObject")

    Set oResults = new ExecResults
    oResults.StdOut = ""
    oResults.StdErr = ""
    oResults.ExitCode = Null

    outFile = CreateTempFile(FSO)
    errFile = CreateTempFile(FSO)

    ' build a command that will capture the stdout, stderr
    runCmd = "%comspec% /c """ & strCommand & " > """ & outFile & """ 2> """ & errFile & """"""

    ' run the command
    oResults.ExitCode = WshShell.Run(runCmd, 0, True)

    ' read the result streams
    oResults.StdOut = ReadTempFile(FSO, outFile)
    oResults.StdErr = ReadTempFile(FSO, errFile)

    Set ExecuteWithResults = oResults
End Function

Function ExecuteAndTraceWithResults(strCommand, tracer)
    Dim oResults, commandElem, outputElem, errOutputElem, eventType
    Set oResults = ExecuteWithResults(strCommand)
    Set ExecuteAndTraceWithResults = oResults

    If oResults.ExitCode = 0 Then eventType = "INFO" Else eventType = "ERROR"

    Set oTraceEvent = tracer.CreateEvent(eventType)

    Set commandElem = oTraceEvent.ownerDocument.CreateElement("Command")
    commandElem.appendChild(oTraceEvent.ownerDocument.CreateTextNode(strCommand))
    Set outputElem = oTraceEvent.ownerDocument.CreateElement("Output")
    If Not IsNull(oResults.StdOut) Then outputElem.appendChild(oTraceEvent.ownerDocument.CreateTextNode(CStr(oResults.StdOut)))
    Set errOutputElem = oTraceEvent.ownerDocument.CreateElement("ErrorOutput")
    If Not IsNull(oResults.StdErr) Then errOutputElem.appendChild(oTraceEvent.ownerDocument.CreateTextNode(CStr(oResults.StdErr)))

    With oTraceEvent.appendChild(oTraceEvent.ownerDocument.CreateElement("ExecuteAndTraceWithResults"))
        .appendChild(commandElem)
        .appendChild(outputElem)
        .appendChild(errOutputElem)
    End With

    tracer.TraceEvent oTraceEvent
End Function

Class ExecResults
    Dim StdOut
    Dim StdErr
    Dim ExitCode
End Class

Function CreateTempFile(FSO)
    Dim folder, file
    Set folder = FSO.GetSpecialFolder(TemporaryFolder)
    file = FSO.GetTempName    
    CreateTempFile = FSO.BuildPath(folder, file)
End Function

Private Function ReadTempFile(FSO, file)
    Dim stream
    Dim str
    str = Null
    Set stream = FSO.OpenTextFile(file, ForReading, False)
    If Not stream.AtEndOfStream Then
        str = stream.ReadAll()
    End If
    stream.Close
    FSO.DeleteFile file
    ReadTempFile = str
End Function

Function GetScriptObject(WScript, scriptPath, componentId)
    Dim FSO, scriptDir
    Set FSO = CreateObject("Scripting.FileSystemObject")
    scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
    Set GetScriptObject = GetObject("script:" & FSO.BuildPath(scriptDir, scriptPath) & "#" & componentId)
End Function

Function TraceError(objTrace, message)
    Dim oTraceEvent
    TraceError = Err.number
    If Err.number <> 0 Then
        Set oTraceEvent = objTrace.CreateEvent("ERROR")
        With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("UnhandledError"))
            With .appendChild(oTraceEvent.ownerDocument.createElement("Message"))
                .text = message
            End With
            With .appendChild(oTraceEvent.ownerDocument.createElement("Number"))
                .text = Err.number
            End With
            With .appendChild(oTraceEvent.ownerDocument.createElement("Description"))
                .text = Err.Description
            End With
            With .appendChild(oTraceEvent.ownerDocument.createElement("Source"))
                .text = Err.Source
            End With
        End With
        objTrace.TraceEvent oTraceEvent
        Err.Clear
    End If
End Function

' gets the active operating system
' function not supported in specialize pass
Function GetCurrentOperatingSystem
    Dim objWMIService, colOS, objItem
    Set GetCurrentOperatingSystem = Nothing
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    Set colOS = objWMIService.ExecQuery ("Select * from Win32_OperatingSystem")
    For Each objItem in colOS
        Set GetCurrentOperatingSystem = objItem
        Exit Function
    Next
End Function

Function LeftPad( strText, intLen, chrPad )
    'LeftPad( "1234", 7, "x" ) = "xxx1234"
    'LeftPad( "1234", 3, "x" ) = "234"
    LeftPad = Right( String( intLen, chrPad ) & strText, intLen )
End Function 