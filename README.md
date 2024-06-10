# MemoryLane
Various malware related projects from long time ago. Majority of them can be adapted to current malware strains


# MemoryLane 1: SpyEye related tools
A long time ago in a galaxy not so far away, a family of banking trojans called SpyEye was widespread. With new samples rolling in daily,
hitting hundreds of banks around the world, we needed automation in handling the sample flood.

SpyEye used a modified, password protected ZIP-file to hold the configuration which told it which banks to hit and how to do it. The password
for the ZIP was an uppercased MD5 hash, 32 bytes long alphanumeric string. While the password was in cleartext inside the malware at runtime,
the malware itself was pretty much always protected by a compressor or an obfuscator which also hid the password from plain sight.

So we devised a way to run all the samples automatically in a virtualized environment. The system created a new malware process in suspended mode,
injected the SpyVsSpy DLL into the process and then let the malware resume on it's way. The DLL inside was waiting for the process to die after the
malware injected itself into another process. When the process began dying, the DLL would be automatically called with DLL_PROCESS_DETACH flag, at
which point the DLL started a memory scan on the process memory, looking for a 32 bytes long uppercased alphanumeric string, a.k.a the password.

If a candidate was found, it was saved to keyring file. Later on, in another tool, an encrypted configuration file was opened by testing all the keys
in the keyring to see which key was used.

Even though nowadays SpyEye is but a distant memory, this technique can still be used to process other malware in similar fashion. 
