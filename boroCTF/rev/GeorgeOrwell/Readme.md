# George Orwell - Reverse Engineering Writeup

## Analysis
The challenge provided a Windows PE executable named `chall`. Upon initial inspection using the `strings` command, I identified that the binary is a compiled **AutoHotkey (AHK)** script.

Key observations from the strings:
- The presence of AHK-related strings like `AutoHotkey`, `RegDeleteKeyExW`, and GUI definitions.
- A hotstring definition: `:*:iloveboroctf::`. This suggests that typing `iloveboroctf` triggers an action.
- A series of `Chr()` calls that construct a variable named `secret`.
- A `MsgBox` call that displays the `secret` variable, which is identified as the flag.

The script fragments found were:
```autohotkey
secret := Chr(98) . Chr(111) . Chr(114) . Chr(111) . Chr(67) . Chr(84) . Chr(70) . Chr(123)
secret := secret . Chr(65) . Chr(72) . Chr(75) . Chr(95) . Chr(49) . Chr(115) . Chr(95)
secret := secret . Chr(108) . Chr(73) . Chr(115) . Chr(43) . Chr(101) . Chr(110) . Chr(105)
secret := secret . Chr(52) . Chr(103) . Chr(125)
MsgBox, 64, System Notification, Access Granted!`n`nFlag: %secret%
```

## Exploitation / Solution
Since the flag is constructed using ASCII values in the `Chr()` function, I simply extracted these values and converted them back to characters using Python.

The ASCII values are:
`[98, 111, 114, 111, 67, 84, 70, 123, 65, 72, 75, 95, 49, 115, 95, 108, 73, 115, 43, 101, 110, 105, 52, 103, 125]`

Reconstructing the string:
- `98, 111, 114, 111, 67, 84, 70, 123` -> `boroCTF{`
- `65, 72, 75, 95, 49, 115, 95` -> `AHK_1s_`
- `108, 73, 115, 43, 101, 110, 105` -> `lIs+eni`
- `52, 103, 125` -> `4g}`

Resulting Flag: `boroCTF{AHK_1s_lIs+eni4g}`

The challenge theme (George Orwell/Big Brother) and the "We are listening" GUI confirm that this script acts like a keylogger or a monitored input handler, waiting for the specific string `iloveboroctf` to reveal the flag.

## Flag
`boroCTF{AHK_1s_lIs+eni4g}`
