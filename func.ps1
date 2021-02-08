function New-CodeChallenge {
  Add-Type -AssemblyName System.Web
  $RandomNumberGenerator = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  $Bytes = New-Object Byte[] 32
  $RandomNumberGenerator.GetBytes($Bytes)
  ([System.Web.HttpServerUtility]::UrlTokenEncode($Bytes)).Substring(0, 43)
}

function Do-DeviceCodeFlow {

  param (
      [String]$clientId   = $azure_pwsh_id,
      [String]$tenantId   = 'common',
      [String]$resource   = 'https://graph.microsoft.com',
      [string]$scope      = 'https://graph.microsoft.com/directory.read%20https://graph.microsoft.com/directory.write',
      [switch]$short,
      [switch]$v2
  )

  if ($v2) {
    $DeviceCodeRequestParams = @{
      Method = 'POST'
      Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
      Body   = @{
          client_id = $clientId
          scope     = $scope
      }
    }
  }
  else {
    $DeviceCodeRequestParams = @{
      Method = 'POST'
      Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/devicecode"
      Body   = @{
          client_id = $clientId
          resource  = $resource
      }
    }
  }

  $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
  Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
  Set-Clipboard $DeviceCodeRequest.user_code 
  if (!$short){
      Add-Type -AssemblyName System.Windows.Forms
      $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
      $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ 
          Width = 440; 
          Height = 600; 
          Url = "https://www.microsoft.com/devicelogin" 
      }
      
      $web.Add_DocumentCompleted($DocComp)
      $web.DocumentText
      $form.Controls.Add($web)
      $form.Add_Shown({ $form.Activate() })
      $web.ScriptErrorsSuppressed = $true
      $form.AutoScaleMode = 'Dpi'
      $form.text = "Graph API Authentication"
      $form.ShowIcon = $False
      $form.AutoSizeMode = 'GrowAndShrink'
      $Form.StartPosition = 'CenterScreen'
      $form.ShowDialog() | Out-Null
      $TokenRequestParams = @{
      Method = 'POST'
      Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
      Body   = @{
          grant_type = "urn:ietf:params:oauth:grant-type:device_code"
          code       = $DeviceCodeRequest.device_code
          client_id  = $clientId
      }
      }
      $global:tkn = Invoke-RestMethod @TokenRequestParams
      $global:tkno = Get-Jwto $tkn.access_token 
  
      Write-Host "`nToken saved as `$tkn"
      $tkno | select aud,iat,exp,app_displayname,appId,upn,amr,scp
  }
}


function Do-ClientCredFlow {

  param ( 
    [string]$clientId             = $m_client_id,
    [string]$clientSecret,        
    [string]$scope                = "https://graph.microsoft.com/.default",
    [string]$tenantId             = "common"
  )

  $grantType            = "client_credentials"
  $url                  = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
  $contentType          = "application/x-www-form-urlencoded"
  if (!$clientSecret) {
    $clientSecret         = Read-Host "Enter client secret"
  }
  $body = @{
    client_id           = $clientId
    scope               = $scope
    client_secret       = $clientSecret
    grant_type          = $grantType
  }
  Invoke-RestMethod -Uri $url -Method POST -Body $body 
}    


function Do-AuthCodeFlow {

  param ( 
    [string]$clientId             = $m_client_id,
    [string]$tenantId             = $m_tenant_id,
    [string]$redirectUri          = $m_redirect_uri,        
    [string]$scope                = "https://graph.microsoft.com/.default",
    [switch]$print
  )

  $url                  = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize"
  $contentType          = "application/x-www-form-urlencoded"

  $Parameters = @{
    client_id               = $clientId
    response_type           = "code"
    redirect_uri            = $redirectUri
    response_mode           = "query"
    scope                   = $scope
    state                   = "12345"
    code_challenge          = $(New-CodeChallenge)
    code_challenge_method   = "S256" 
  }

  $HttpValueCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
  foreach ($Item in $Parameters.GetEnumerator()) {
    if ($Item.Value.Count -gt 1) {
      foreach ($Value in $Item.Value) {
          $ParameterName = $Item.Key
          if ($AddSquareBracketsToArrayParameters) { $ParameterName += '[]' }                 
          $HttpValueCollection.Add($ParameterName, $Value)
        }
    } else {
        $HttpValueCollection.Add($Item.Key,$Item.Value)
    }
  }
  $Request  = [System.UriBuilder]($url)
  $Request.Query = $HttpValueCollection.ToString()
  if ($print){
    $Request.Uri.AbsoluteUri
  }
  else {
    Invoke-WebRequest -Uri $Request.Uri -Method GET
  }
}    

function New-Output($Coll, $Type, $Directory) {
    
  $Count = $Coll.Count

  Write-Host "Writing output for $($Type)"
if ($null -eq $Coll) {
      $Coll = New-Object System.Collections.ArrayList
  }
  $Directory = "$env:USERPROFILE/bh2/"
  $Output = New-Object PSObject
  $Meta = New-Object PSObject
  $Meta | Add-Member Noteproperty 'count' $Coll.Count
  $Meta | Add-Member Noteproperty 'type' "az$($Type)"
  $Meta | Add-Member Noteproperty 'version' 4
  $Output | Add-Member Noteproperty 'meta' $Meta
  $Output | Add-Member Noteproperty 'data' $Coll
  $FileName = $Directory + "\" + "`$date" + "-" + "az" + $($Type) + ".json"
  $Output | ConvertTo-Json | Out-File -Encoding "utf8" -FilePath $FileName  
}

function Get-JWTO {
  param (
      [string]$JWT,
      [switch]$o
  )

  if ($JWT.getType().Name -ne 'Object') {
      $obj = ''
      $split = $JWT.split('.') 
      $num = ($split.count - 1)
      $res = ''
      $output = New-Object psobject
      0..$num | %{
          $r = $split[$_].Replace('-', '+').Replace('_', '/')
          while ($r.Length % 4) { $r += "=" }
          $bytes = [System.Convert]::FromBase64String($r)
          $string = ([System.Text.Encoding]::ASCII.GetString($bytes)) 
          if ($string.StartsWith('{')) {
              $res += $string
          }
          if ($string.StartsWith('"')) {
              $string = [regex]::Unescape($string).trim('"')
              $res += $string
          }
      }
      $obj = $res.replace('}{',',') | ConvertFrom-Json

      if ($obj.iat) {
      $issTime = (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($obj.iat) 
      $obj.iat = [System.TimeZoneInfo]::ConvertTimeFromUtc($issTime, [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time'))
      }
      if ($obj.exp) {
          $expTime = (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($obj.exp)
          $obj.exp = [System.TimeZoneInfo]::ConvertTimeFromUtc($expTime, [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time'))
      }
      if ($obj.nbf) {
          $notBefore = (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($obj.nbf)
          $obj.nbf = [System.TimeZoneInfo]::ConvertTimeFromUtc($notBefore, [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time'))
      }  
      if (($obj.exp) -and ($obj.iat)) {
          $timeValid = [datetime]$obj.exp - [datetime]$obj.iat
          $obj | Add-Member -MemberType NoteProperty -Name validFor -Value $timeValid
      }
  }
  else { $obj = $JWT  }

  if ($obj.aud -match "^[a-f0-9]{8}\-"){
      $obj.aud = "$($obj.aud) ( $(Get-AppId $obj.aud) )"
  }    
  if ($obj.upn){
      $obj = $obj | Select-Object -Property * -ExcludeProperty family_name,given_name,unique_name,name
  }
  if ($obj.appid){
      $obj.appid = "$($obj.appid) ( $(Get-AppId $obj.appid) )"
  }
  if ($obj.deviceid){
      $obj.deviceid = "$($obj.deviceid) ( $(Get-DevName $obj.deviceid) )"
  }
  if ($obj.scp -match '^\d'){
      $obj.scp = "$($obj.deviceid) ( $(Get-RoleName $obj.scp) )"
  }    

  $obj = $obj | Select-Object -Property * -ExcludeProperty rh,tid,uti,ver,nonce,x5t,kid,alg,typ

  if ($o) {
    $obj
  }
  else {
    $obj | Out-HostColored -Pattern 'aud\s+:.*','upn\s+:.*','scp\s+:[^\n]+','amr\s+:.*','appid\s+:.*','deviceid\s+:.*' -ForegroundColor Green
  }
}  

function Out-HostColored {
  # Note: The [CmdletBinding()] and param() block are formatted to be PSv2-compatible.
  [CmdletBinding()]
  param(
      [Parameter(Position = 0, Mandatory = $True)] [string[]] $Pattern,
      [Parameter(Position = 1)] [ConsoleColor] $ForegroundColor = 'Green',
      [Parameter(Position = 2)] [ConsoleColor] $BackgroundColor,
      [switch] $WholeLine,
      [switch] $SimpleMatch,
      [Parameter(Mandatory = $True, ValueFromPipeline = $True)] $InputObject
  )

  try {
      $re = [regex] ('(?<sep>{0})' -f $(if ($SimpleMatch) { 
          ($Pattern | ForEach-Object { [regex]::Escape($_) }) -join '|'
          } 
          else { 
          ($Pattern | ForEach-Object { '(?:{0})' -f $_ }) -join '|'
          }))
  }
  catch { Throw }

  $htColors = @{
      ForegroundColor = $ForegroundColor
  }
  if ($BackgroundColor) {
      $htColors.Add('BackgroundColor', $BackgroundColor)
  }

  # Use pipeline input, if provided (the typical case).
  if ($MyInvocation.ExpectingInput) { $InputObject = $Input }

  $InputObject | Out-String -Stream | ForEach-Object {
      $line = $_
      if ($WholeLine) {
          if ($line -match $re) {
              Write-Host @htColors $line
          }
          else {
              Write-Host $line
          }
      }
      else {
          $segments = $line -split $re, 0, 'ExplicitCapture'
          if ($segments.Count -eq 1) {
              Write-Host $line
          }
          else {
              $i = 0
              foreach ($segment in $segments) {
                  if ($i++ % 2) {
                      Write-Host -NoNewline @htColors $segment
                  }
                  else {
                      Write-Host -NoNewline $segment
                  }
              }
              Write-Host '' # Terminate the current output line with a newline.
          }
      }
  }
}

function Get-AzTokenFromContext ($res) {
  $res = "https://" + $res
  $context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
  $azToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id.ToString(), $null,[Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $res).AccessToken
  $azToken
}
function Get-AzTokenFromCache {

  $token = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken']
  if ($token) {
      $token.AccessToken
  }
  else {
      return "No token obtained"
  }
}
function Do-Alias {
  Set-Alias -Name gj -Value "Get-JWTO" -Scope Global
}
function urlDecode($u){
  if (![System.Web.HttpUtility]){
    Add-Type -AssemblyName System.Web
  }
  [System.Web.HttpUtility]::UrlDecode($u)
}
function urlEncode($u){
  if (![System.Web.HttpUtility]){
    Add-Type -AssemblyName System.Web
  }
  [System.Web.HttpUtility]::UrlEncode($u)
}
function ConvertTo-Base64 {
  param (
      
      [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
      [string]$String,
      
      [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
      [switch]$unicode
  )

  if ($unicode) {
      Write-Output ([System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($String)))
  }
  else {
      Write-Output ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($String)))
  }
}
function ConvertFrom-Base64 {
  param (
      [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
      [string]$Base64String,
      
      [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
      [switch]$unicode
  )

  if ($unicode){
     $stringBytes = [System.Convert]::FromBase64String($Base64String)
     Write-Output ([System.Text.Encoding]::Unicode.GetString($stringBytes))
  }
  else {
      $stringBytes = [System.Convert]::FromBase64String($Base64String)
      Write-Output ([System.Text.Encoding]::ASCII.GetString($stringBytes))
  }
}
function Enable-PowerShellHttps {
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
  add-type @"
  using System.Net;
  using System.Security.Cryptography.X509Certificates;
  public class TrustAllCertsPolicy : ICertificatePolicy {
      public bool CheckValidationResult(
          ServicePoint srvPoint, X509Certificate certificate,
          WebRequest request, int certificateProblem) {
          return true;
      }
  }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
}
}
function Enable-PowerShellHttps {
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
  add-type @"
  using System.Net;
  using System.Security.Cryptography.X509Certificates;
  public class TrustAllCertsPolicy : ICertificatePolicy {
      public bool CheckValidationResult(
          ServicePoint srvPoint, X509Certificate certificate,
          WebRequest request, int certificateProblem) {
          return true;
      }
  }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
}
}
function Get-CredObj ($upn) {
  if ($password) {
      $secPass = ConvertTo-SecureString $password -AsPlainText -Force
      New-Object System.Management.Automation.PSCredential ($upn, $secPass)
  }
  else {
      Write-Host -Fore Red "[-] " -NoNewLine; Write-Host "No password (`$password)`n"
  }
}

function Get-KerberosToken {
  $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  # $groupSIDs = $token.Groups 
  # foreach($sid in $groupSIDs) {
  #   try {
  #     Write-Host (($sid).Translate([System.Security.Principal.NTAccount])) 
  #   }
  #   catch {
  #     Write-Warning ("Could not translate " + $sid.Value + ". Reason: " + $_.Exception.Message)
  #   }
  # }
  $token
}

Function Get-SmartCardCred{

  [cmdletbinding()]
  param()
  
  $SmartCardCode = @"
  // Copyright (c) Microsoft Corporation. All rights reserved.
  // Licensed under the MIT License.
  
  using System;
  using System.Management.Automation;
  using System.Runtime.InteropServices;
  using System.Security;
  using System.Security.Cryptography.X509Certificates;
  
  
  namespace SmartCardLogon{
  
      static class NativeMethods
      {
  
          public enum CRED_MARSHAL_TYPE
          {
              CertCredential = 1,
              UsernameTargetCredential
          }
  
          [StructLayout(LayoutKind.Sequential)]
          internal struct CERT_CREDENTIAL_INFO
          {
              public uint cbSize;
              [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
              public byte[] rgbHashOfCert;
          }
  
          [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
          public static extern bool CredMarshalCredential(
              CRED_MARSHAL_TYPE CredType,
              IntPtr Credential,
              out IntPtr MarshaledCredential
          );
  
          [DllImport("advapi32.dll", SetLastError = true)]
          public static extern bool CredFree([In] IntPtr buffer);
  
      }    
      public class Certificate
      {    
          public static PSCredential MarshalFlow(string thumbprint, SecureString pin)
          {
              //
              // Set up the data struct
              //
              NativeMethods.CERT_CREDENTIAL_INFO certInfo = new NativeMethods.CERT_CREDENTIAL_INFO();
              certInfo.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.CERT_CREDENTIAL_INFO));    
              //
              // Locate the certificate in the certificate store 
              //
              X509Certificate2 certCredential = new X509Certificate2();
              X509Store userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
              userMyStore.Open(OpenFlags.ReadOnly);
              X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
              userMyStore.Close();   
              if (certsReturned.Count == 0)
              {
                  throw new Exception("Unable to find the specified certificate.");
              }   
              //
              // Marshal the certificate 
              //
              certCredential = certsReturned[0];
              certInfo.rgbHashOfCert = certCredential.GetCertHash();
              int size = Marshal.SizeOf(certInfo);
              IntPtr pCertInfo = Marshal.AllocHGlobal(size);
              Marshal.StructureToPtr(certInfo, pCertInfo, false);
              IntPtr marshaledCredential = IntPtr.Zero;
              bool result = NativeMethods.CredMarshalCredential(NativeMethods.CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);    
              string certBlobForUsername = null;
              PSCredential psCreds = null;   
              if (result)
              {
                  certBlobForUsername = Marshal.PtrToStringUni(marshaledCredential);
                  psCreds = new PSCredential(certBlobForUsername, pin);
              }
  
              Marshal.FreeHGlobal(pCertInfo);
              if (marshaledCredential != IntPtr.Zero)
              {
                  NativeMethods.CredFree(marshaledCredential);
              }   
              return psCreds;
          }
      }
  }
"@
  Add-Type -TypeDefinition $SmartCardCode -Language CSharp
  Add-Type -AssemblyName System.Security
  $global:ValidCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](dir Cert:\CurrentUser\My)
  $global:cert = $ValidCerts | ? NotAfter -gt "1/1/2022" | ? EnhancedKeyUsageList -match "Smart"
  $pin = Read-Host "Enter your PIN" -AsSecureString
  Write-Output ([SmartCardLogon.Certificate]::MarshalFlow($cert.Thumbprint, $pin))
}




