import "pe"

rule potential_process_herpaderping
{
  meta:
    description = "Detects potential use of Process Herpaderping. It is a method of obscuring the intentions of a process by modifying the content on disk after the image has been mapped"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    author = "@Cyb3rWard0g, @OTR_Community"
    date = "2020-10-27"
    reference="https://twitter.com/jxy__s/status/1320853852153769984"

    hash="4eb7d1e1bab6c69fe5e0f2566e720021715381b182b9d50a5d591008c37f69f7"
	strings:
		$s1 = "Herpaderp::ExecuteProcess" wide ascii
  condition:
  // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D
    and all of ($s*)
    // Write target binary to disk, keeping the handle open. This is what will execute in memory.
    // Copied source binary to target file
    and pe.imports("kernel32.dll", "CreateFileW")
    // Map the file as an image section (Created image section for target)
    and pe.imports("ntdll.dll", "NtCreateSection")
    // Create the process object using the section handle
    and pe.imports("ntdll.dll", "NtCreateProcessEx")
    and pe.imports("kernel32.dll", "GetProcessId")
    // Locate target image entry RVA
    and pe.imports("kernel32.dll", "CreateFileMappingW")
    and pe.imports("kernel32.dll", "MapViewOfFile")
    // Overwrite the target binary with another
    // CopyFileByHandle
    and pe.imports("kernel32.dll", "ReadFile")
    and pe.imports("kernel32.dll", "WriteFile")
    // Preparing target for execution
    and pe.imports("ntdll.dll", "NtQueryInformationProcess")
    and pe.imports("kernel32.dll", "ReadProcessMemory")
    and pe.imports("kernel32.dll", "VirtualAllocEx")
    and pe.imports("kernel32.dll", "WriteProcessMemory")
    // Create the initial thread in the process
    and pe.imports("ntdll.dll", "NtCreateThreadEx")
}