' sslopencrypt_macro.bas
' LibreOffice Basic macro for sslOpenCrypt integration.
'
' Provides toolbar/menu operations to sign, verify, encrypt, and hash the
' active document by communicating with the sslOpenCrypt IPC server running
' on localhost:47251.
'
' Installation:
'   1. Start the IPC server:
'        python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py &
'
'   2. In LibreOffice, open: Tools → Macros → Organise Basic Macros
'      Create a new module and paste this entire file.
'
'   3. Assign macros to menu items or toolbar buttons via:
'      Tools → Customise → Keyboard / Menus / Toolbars
'
' Alternatively, place this file as:
'   ~/.config/libreoffice/4/user/Scripts/basic/sslOpenCrypt/Module1.xba
' and it will appear under Tools → Macros → sslOpenCrypt.
'
' IPC protocol: newline-delimited JSON over TCP to 127.0.0.1:47251
' The server is NOT accessible from the network (loopback only).

Option Explicit

Const IPC_HOST As String = "127.0.0.1"
Const IPC_PORT As Integer = 47251

' ---------------------------------------------------------------------------
' Low-level: send a JSON request to the IPC server, return JSON response
' ---------------------------------------------------------------------------
Private Function SendRequest(sJson As String) As String
    Dim oSocket As Object
    Dim sResponse As String
    On Error GoTo ErrHandler

    oSocket = CreateUnoService("com.sun.star.bridge.UnoUrlResolver")
    ' LibreOffice Basic does not have a native TCP socket API.
    ' We use the Shell() function to call Python for the actual send.
    Dim sPy As String
    sPy = "python3 -c """ & _
        "import socket, json, sys;" & _
        "s = socket.create_connection(('" & IPC_HOST & "', " & IPC_PORT & "), timeout=30);" & _
        "s.sendall(sys.argv[1].encode() + b'\n');" & _
        "d = b''; " & _
        "[d.__iadd__(s.recv(4096)) for _ in range(100) if b'\n' not in d];" & _
        "print(d.split(b'\n')[0].decode())" & _
        """ """ & Shell_EscapeArg(sJson) & """"

    Dim oShell As Object
    oShell = CreateUnoService("com.sun.star.bridge.UnoUrlResolver")

    ' Use Shell + temp file approach (cross-platform, no native socket needed)
    Dim sTmpOut As String
    sTmpOut = ConvertToURL(Environ("TMPDIR") & "/sslopencrypt_response.json")
    If sTmpOut = "" Then
        sTmpOut = ConvertToURL("/tmp/sslopencrypt_response.json")
    End If

    Dim sCmd As String
    sCmd = "python3 -c """ & _
        "import socket,json,sys;" & _
        "req=" & Chr(34) & sJson & Chr(34) & ";" & _
        "s=socket.create_connection(('" & IPC_HOST & "'," & IPC_PORT & "),timeout=30);" & _
        "s.sendall(req.encode()+b'\n');" & _
        "d=b'';" & Chr(10) & _
        "while b'\n' not in d: d+=s.recv(4096);" & Chr(10) & _
        "open('/tmp/sslopencrypt_response.json','w').write(d.split(b'\n')[0].decode())" & """"

    Shell "bash -c " & Chr(34) & sCmd & Chr(34)
    Wait 1500  ' give python time to write the file

    ' Read the response
    Dim iFile As Integer
    iFile = FreeFile()
    Open ConvertFromURL(sTmpOut) For Input As #iFile
    Dim sLine As String
    Do While Not EOF(iFile)
        Line Input #iFile, sLine
        sResponse = sResponse & sLine
    Loop
    Close #iFile

    SendRequest = sResponse
    Exit Function

ErrHandler:
    SendRequest = "{""success"":false,""error"":""IPC connection failed. Is the sslOpenCrypt server running? Start with: python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py""}"
End Function

' ---------------------------------------------------------------------------
' Escape a string for shell argument (single-quote wrap with ' -> '\'' )
' ---------------------------------------------------------------------------
Private Function Shell_EscapeArg(s As String) As String
    Shell_EscapeArg = "'" & Join(Split(s, "'"), "'\''") & "'"
End Function

' ---------------------------------------------------------------------------
' Helper: get the path of the active document
' ---------------------------------------------------------------------------
Private Function GetActiveDocPath() As String
    Dim oDoc As Object
    oDoc = ThisComponent
    If IsNull(oDoc) Or IsEmpty(oDoc) Then
        MsgBox "No document is open.", MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt"
        GetActiveDocPath = ""
        Exit Function
    End If
    Dim sUrl As String
    sUrl = oDoc.getURL()
    If sUrl = "" Then
        MsgBox "Please save the document before performing cryptographic operations.", _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt"
        GetActiveDocPath = ""
        Exit Function
    End If
    GetActiveDocPath = ConvertFromURL(sUrl)
End Function

' ---------------------------------------------------------------------------
' Parse a JSON key-value from a simple flat JSON string (no nested objects)
' ---------------------------------------------------------------------------
Private Function JsonGetString(sJson As String, sKey As String) As String
    Dim sSearch As String
    sSearch = Chr(34) & sKey & Chr(34) & ":"
    Dim iStart As Long, iEnd As Long
    iStart = InStr(sJson, sSearch)
    If iStart = 0 Then
        JsonGetString = ""
        Exit Function
    End If
    iStart = iStart + Len(sSearch)
    ' Skip whitespace and opening quote
    Do While Mid(sJson, iStart, 1) = " " Or Mid(sJson, iStart, 1) = Chr(9)
        iStart = iStart + 1
    Loop
    If Mid(sJson, iStart, 1) = Chr(34) Then
        iStart = iStart + 1
        iEnd = InStr(iStart, sJson, Chr(34))
        JsonGetString = Mid(sJson, iStart, iEnd - iStart)
    Else
        ' Boolean or number
        iEnd = InStr(iStart, sJson, ",")
        If iEnd = 0 Then iEnd = InStr(iStart, sJson, "}")
        If iEnd = 0 Then iEnd = Len(sJson) + 1
        JsonGetString = Trim(Mid(sJson, iStart, iEnd - iStart))
    End If
End Function

' ---------------------------------------------------------------------------
' Public macros — assign these to menu/toolbar items
' ---------------------------------------------------------------------------

' Sign the active document (creates <docname>.p7s alongside the document)
Public Sub SignDocument()
    Dim sFile As String
    sFile = GetActiveDocPath()
    If sFile = "" Then Exit Sub

    Dim sReq As String
    sReq = "{""op"":""sign"",""file"":""" & sFile & """}"
    Dim sResp As String
    sResp = SendRequest(sReq)

    Dim bSuccess As Boolean
    bSuccess = (JsonGetString(sResp, "success") = "true")
    If bSuccess Then
        Dim sSig As String
        sSig = JsonGetString(sResp, "output")
        MsgBox "Document signed successfully." & Chr(13) & "Signature file: " & sSig, _
               MB_OK + MB_ICONINFORMATION, "sslOpenCrypt — Signed"
    Else
        MsgBox "Signing failed:" & Chr(13) & JsonGetString(sResp, "error"), _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt — Error"
    End If
End Sub

' Verify the signature for the active document (looks for <docname>.p7s)
Public Sub VerifySignature()
    Dim sFile As String
    sFile = GetActiveDocPath()
    If sFile = "" Then Exit Sub

    Dim sSigFile As String
    sSigFile = InputBox("Signature file (.p7s):", "sslOpenCrypt — Verify", sFile & ".p7s")
    If sSigFile = "" Then Exit Sub

    Dim sReq As String
    sReq = "{""op"":""verify"",""file"":""" & sFile & """,""signature"":""" & sSigFile & """}"
    Dim sResp As String
    sResp = SendRequest(sReq)

    Dim bSuccess As Boolean
    bSuccess = (JsonGetString(sResp, "success") = "true")
    If bSuccess Then
        MsgBox "Signature VALID." & Chr(13) & JsonGetString(sResp, "result"), _
               MB_OK + MB_ICONINFORMATION, "sslOpenCrypt — Verified"
    Else
        MsgBox "Signature INVALID or verification failed:" & Chr(13) & _
               JsonGetString(sResp, "error"), _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt — Verification Failed"
    End If
End Sub

' Compute SHA-256 hash of the active document
Public Sub HashDocument()
    Dim sFile As String
    sFile = GetActiveDocPath()
    If sFile = "" Then Exit Sub

    Dim sAlg As String
    sAlg = InputBox("Hash algorithm:", "sslOpenCrypt — Hash", "SHA-256")
    If sAlg = "" Then sAlg = "SHA-256"

    Dim sReq As String
    sReq = "{""op"":""hash"",""file"":""" & sFile & """,""algorithm"":""" & sAlg & """}"
    Dim sResp As String
    sResp = SendRequest(sReq)

    Dim bSuccess As Boolean
    bSuccess = (JsonGetString(sResp, "success") = "true")
    If bSuccess Then
        MsgBox sAlg & " digest:" & Chr(13) & Chr(13) & JsonGetString(sResp, "result"), _
               MB_OK + MB_ICONINFORMATION, "sslOpenCrypt — Hash"
    Else
        MsgBox "Hash failed:" & Chr(13) & JsonGetString(sResp, "error"), _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt — Error"
    End If
End Sub

' Encrypt the active document with AES-256-GCM
Public Sub EncryptDocument()
    Dim sFile As String
    sFile = GetActiveDocPath()
    If sFile = "" Then Exit Sub

    Dim sPass As String
    sPass = InputBox("Passphrase for encryption:", "sslOpenCrypt — Encrypt", "")
    If sPass = "" Then
        MsgBox "Encryption cancelled (no passphrase entered).", MB_OK, "sslOpenCrypt"
        Exit Sub
    End If

    Dim sOutput As String
    sOutput = sFile & ".enc"

    Dim sReq As String
    sReq = "{""op"":""encrypt"",""file"":""" & sFile & """," & _
           """output"":""" & sOutput & """," & _
           """cipher"":""AES-256-GCM""," & _
           """passphrase"":""" & sPass & """}"
    Dim sResp As String
    sResp = SendRequest(sReq)

    Dim bSuccess As Boolean
    bSuccess = (JsonGetString(sResp, "success") = "true")
    If bSuccess Then
        MsgBox "Document encrypted." & Chr(13) & "Output: " & sOutput, _
               MB_OK + MB_ICONINFORMATION, "sslOpenCrypt — Encrypted"
    Else
        MsgBox "Encryption failed:" & Chr(13) & JsonGetString(sResp, "error"), _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt — Error"
    End If
End Sub

' Check if the IPC server is reachable
Public Sub CheckServer()
    Dim sReq As String
    sReq = "{""op"":""hash"",""file"":""/dev/null"",""algorithm"":""SHA-256""}"
    Dim sResp As String
    sResp = SendRequest(sReq)

    If InStr(sResp, """success"":true") > 0 Then
        MsgBox "sslOpenCrypt IPC server is running on port " & IPC_PORT & ".", _
               MB_OK + MB_ICONINFORMATION, "sslOpenCrypt — Server Status"
    Else
        MsgBox "Cannot reach sslOpenCrypt IPC server." & Chr(13) & Chr(13) & _
               "Start the server:" & Chr(13) & _
               "python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py", _
               MB_OK + MB_ICONEXCLAMATION, "sslOpenCrypt — Server Not Running"
    End If
End Sub
