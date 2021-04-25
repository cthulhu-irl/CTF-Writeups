# Tertiary

## info

given a 64bit binary, we ought to reverse it... :)

```
$ file tertiary
tertiary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ef9b1157350591276bf6b2e01ae05bf3dbc64bfd, stripped
```

decompiler gives this for `main` function:
```c

// WARNING: Could not reconcile some variable overlaps
// WARNING: [r2ghidra] Failed to match type signed int64_t for variable var_b8h to Decompiler type: Unknown type
// identifier signed
// WARNING: [r2ghidra] Failed to match type signed int64_t for variable var_b4h to Decompiler type: Unknown type
// identifier signed
// WARNING: [r2ghidra] Detected overlap for variable var_b4h

undefined8 main(void)
{
    int64_t iVar1;
    undefined8 uVar2;
    int64_t in_FS_OFFSET;
    undefined8 var_b8h;
    char *var_b0h;
    char *var_a8h;
    char *var_a0h;
    char *s;
    int64_t var_88h;
    int64_t var_80h;
    int64_t var_78h;
    int64_t var_70h;
    int64_t var_68h;
    int64_t var_60h;
    int64_t var_58h;
    int64_t var_50h;
    int64_t var_48h;
    int64_t var_40h;
    int64_t var_38h;
    int64_t var_30h;
    int64_t var_28h;
    int64_t var_20h;
    int64_t var_18h;
    int64_t canary;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_b0h = "Y_rssr_3_UOSTr3e50_s_lsR_c_0cf";
    s = (char *)0x0;
    var_b8h._0_4_ = 0;
    while ((int32_t)var_b8h < 0x1e) {
        var_b8h._4_4_ = 0;
        while (var_b8h._4_4_ < 3) {
            *(char *)((int64_t)&s + (int64_t)(var_b8h._4_4_ + (int32_t)var_b8h * 3)) =
                 (&var_b0h)[var_b8h._4_4_][(int32_t)var_b8h];
            var_b8h._4_4_ = var_b8h._4_4_ + 1;
        }
        var_b8h._0_4_ = (int32_t)var_b8h + 1;
    }
    .plt.sec(&s);
    uVar2 = 0;
    if (iVar1 != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar2 = __stack_chk_fail();
    }
    return uVar2;
}
```

it's not quite right... looking at its disassembly too, I found it roughly translates to this:
```c
#include <stdio.h>

int main() {
  const char *s[3] = {
    "Y_rssr_3_UOSTr3e50_s_lsR_c_0cf",
    "0}3om7tRy__4F3r__oeY_e_a4U{foe",
    "ua__4!heog_C{vsis04}{7gb_p}_F3"
  };
  char flag[4 * 31] = { 0 };

  for (int i = 0; i < 30; i++) {
    for (int j = 0; j < 3; j++) {
      flag[i * 3 + j] = s[j][i];
    }
  }

  printf("%p\n", flag);

  return 0;
}
```

## solution

having reverse the code... I just updated my code to print the flag itself instead of its address:
```c
printf("%s\n", flag);
```

and just compiled and ran it...

