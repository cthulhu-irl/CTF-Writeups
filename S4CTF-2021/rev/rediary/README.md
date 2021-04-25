# RE Diary

## info

we're given an ELF file along with `flag.enc` (encoded flag) to reverse engineer and decode the `flag.enc`.

decompiled code of `main` function:
```c
    std::allocator<char>::allocator()(&var_51h);
    fcn.00002c8a((int64_t)&var_51h + 1);
    fcn.00002e9c((int64_t)&var_40h, (int64_t)&var_260h);
    fcn.00002ee8((int64_t)&var_280h, var_40h, var_38h, stack0xffffffffffffffa8, var_48h, (int64_t)&var_51h);
    std::allocator<char>::~allocator()(&var_51h);
    std::basic_ifstream<char, std::char_traits<char> >::close()(&var_260h);
    
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
              (&var_30h, &var_280h, &var_280h);
    fcn.00002444((int64_t)&var_2a0h, (int64_t)&var_30h);
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()(&var_30h);
    std::basic_ofstream<char, std::char_traits<char> >::basic_ofstream(char const*, std::_Ios_Openmode)
              (&var_4a0h, "flag.enc", 0x10);
    
    std::basic_ostream<char, std::char_traits<char> >& std::operator<< <char, std::char_traits<char>, std::allocator<char> >(std::basic_ostream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
              (&var_4a0h, &var_2a0h, &var_2a0h);
    std::basic_ofstream<char, std::char_traits<char> >::close()(&var_4a0h);
    std::basic_ofstream<char, std::char_traits<char> >::~basic_ofstream()(&var_4a0h);
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()(&var_2a0h);
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()(&var_280h);
    std::basic_ifstream<char, std::char_traits<char> >::~basic_ifstream()(&var_260h);
    return 0;
```

it's C++... and C++ is good at making it a bit harder to reverse engineer...

after wandering around a bit... I found `fcn.00002444` the encrypting function.. and reversed it to this which isn't accurate:
```c
#include <iostream>
#include <string>

int getbit(int x, int n) {
  return (x & (1 << n)) >> n;
}

int is_all_zero(std::string arg) {
  for (auto ch : arg)
    if (ch != '0')
      return 0;

  return 1;
}

std::string some_func(std::string inp) {
  std::string ret = "";
  char var_100h[7][4] = {
    { 0, 1, 1, 1 },
    { 1, 0, 1, 1 },
    { 1, 0, 0, 0 },
    { 0, 1, 0, 0 },
    { 1, 1, 1, 0 },
    { 0, 0, 1, 0 },
    { 0, 0, 0, 1 }
  };

  size_t counter = 0;

  for (char chr : inp) {
    std::string chh_str = "";
    std::string chl_str = "";

    for (int i = 0; i < 7; ++i) {
      char chl = 0, chh = 0;

      for (int j = 0; j < 4; ++j) {
        int k = 3 - j;

        chh += var_100h[i][j] * getbit(chr >> 4, k);
        chl += var_100h[i][j] * getbit(chr & 0xf, k);
      }

      chh_str += '0' + (chh & 1);
      chl_str += '0' + (chl & 1);
    }

    chh_str += is_all_zero(chh_str)       ? '0' : '1';
    chl_str += (not is_all_zero(chl_str)) ? '0' : '1';

    char high = std::strtol(chh_str.c_str(), nullptr, 2);
    char low = std::strtol(chl_str.c_str(), nullptr, 2);

    auto x = ((counter & 1) == 0) ? low : high;
    ret.insert(0, 1, x);

    counter++;

    ret += ((counter & 1) == 1) ? low : high;
  }

  return ret;
}
```

but it clears what it does somehow...

## solution

looking at that function, I decided not to go the rough way... and chose the easy exploit...

the encode method makes a pair of bytes, inserts one at head and one at tail of output string, and making that pair isn't relied on any other character in input...

it kinda depends on the order in sense of current index being even or odd...

so I had put all possible byte values `bytes(range(256))` in `flag` file and encoded it using the given executable `rediary`...

extracted the pairs from the generated `flag.enc`, and reordered them to use for reverse dictionary:
```python
>>> open('flag', 'wb').write(bytes(range(256)))
256
>>> # invoke ./rediary to encode it
>>> 
>>> x = open('flag.enc', 'rb').read()
>>> 
>>> x
b'\xff<\xff\xf0\xff\xa4\xffh\xffT\xff\x98\xff\xcc\xff\x01=<=\xf0=\xa4=h=T=\x98=\xcc=\x013<3\xf03\xa43h3T3\x983\xcc3\x01\xf1<\xf1\xf0\xf1\xa4\xf1h\xf1T\xf1\x98\xf1\xcc\xf1\x01g<g\xf0g\xa4ghgTg\x98g\xccg\x01\xa5<\xa5\xf0\xa5\xa4\xa5h\xa5T\xa5\x98\xa5\xcc\xa5\x01\xab<\xab\xf0\xab\xa4\xabh\xabT\xab\x98\xab\xcc\xab\x01i<i\xf0i\xa4ihiTi\x98i\xcci\x01\x97<\x97\xf0\x97\xa4\x97h\x97T\x97\x98\x97\xcc\x97\x01U<U\xf0U\xa4UhUTU\x98U\xccU\x01[<[\xf0[\xa4[h[T[\x98[\xcc[\x01\x99<\x99\xf0\x99\xa4\x99h\x99T\x99\x98\x99\xcc\x99\x01\x0f<\x0f\xf0\x0f\xa4\x0fh\x0fT\x0f\x98\x0f\xcc\x0f\x01\xcd<\xcd\xf0\xcd\xa4\xcdh\xcdT\xcd\x98\xcd\xcc\xcd\x01\xc3<\xc3\xf0\xc3\xa4\xc3h\xc3T\xc3\x98\xc3\xcc\xc3\x01\x00<\x00\xf0\x00\xa4\x00h\x00T\x00\x98\x00\xcc\x00\x01\x00\xc2\x00\x0e\x00Z\x00\x96\x00\xaa\x00f\x002\x00\xfe\xc3\xc2\xc3\x0e\xc3Z\xc3\x96\xc3\xaa\xc3f\xc32\xc3\xfe\xcd\xc2\xcd\x0e\xcdZ\xcd\x96\xcd\xaa\xcdf\xcd2\xcd\xfe\x0f\xc2\x0f\x0e\x0fZ\x0f\x96\x0f\xaa\x0ff\x0f2\x0f\xfe\x99\xc2\x99\x0e\x99Z\x99\x96\x99\xaa\x99f\x992\x99\xfe[\xc2[\x0e[Z[\x96[\xaa[f[2[\xfeU\xc2U\x0eUZU\x96U\xaaUfU2U\xfe\x97\xc2\x97\x0e\x97Z\x97\x96\x97\xaa\x97f\x972\x97\xfei\xc2i\x0eiZi\x96i\xaaifi2i\xfe\xab\xc2\xab\x0e\xabZ\xab\x96\xab\xaa\xabf\xab2\xab\xfe\xa5\xc2\xa5\x0e\xa5Z\xa5\x96\xa5\xaa\xa5f\xa52\xa5\xfeg\xc2g\x0egZg\x96g\xaagfg2g\xfe\xf1\xc2\xf1\x0e\xf1Z\xf1\x96\xf1\xaa\xf1f\xf12\xf1\xfe3\xc23\x0e3Z3\x963\xaa3f323\xfe=\xc2=\x0e=Z=\x96=\xaa=f=2=\xfe\xff\xc2\xff\x0e\xffZ\xff\x96\xff\xaa\xfff\xff2\xff\xfe'
>>> 
>>> make_pairs = lambda a, ln: list(map(bytes, zip(a[:ln//2][::-1], a[ln//2:])))
>>> 
>>> make_pairs(x, len(x))
[b'\x01\x00', b'\x00\xc2', b'\xcc\x00', b'\x00\x0e', b'\x98\x00', b'\x00Z', b'T\x00', b'\x00\x96', b'h\x00', b'\x00\xaa', b'\xa4\x00', ... ]
```

I did the same for odds by encoding adding a single byte at first `b'A' + bytes(range(256))`... and trim that first one by `make_pairs(x, len(x))[1:]`...

then I hardcoded those list of pairs as `evens` and `odds`... so then I could construct the reverse table like this:
```
charmap = bytes(range(256)) * 2
table = {pair: charmap[i] for i, pair in enumerate(evens + odds)}
```

although it was lacking some pairs, so if `table[pair]` failed, then I would try `table[pair[::-1]]` and even if that failed too, I would fall back on `pair[0]`...

running it on actual `flag.enc`, it'll give us a PDF and when opening it, we'll see the flag...

decoder.py
```python
import sys
import string

evens = [
    b'\x01\x00', b'\x00\xc2', b'\xcc\x00', b'\x00\x0e',
    b'\x98\x00', b'\x00Z', b'T\x00', b'\x00\x96', b'h\x00',
    b'\x00\xaa', b'\xa4\x00', b'\x00f', b'\xf0\x00', b'\x002',
    b'<\x00', b'\x00\xfe', b'\x01\xc3', b'\xc3\xc2',
    b'\xcc\xc3', b'\xc3\x0e', b'\x98\xc3', b'\xc3Z', b'T\xc3',
    b'\xc3\x96', b'h\xc3', b'\xc3\xaa', b'\xa4\xc3', b'\xc3f',
    b'\xf0\xc3', b'\xc32', b'<\xc3', b'\xc3\xfe', b'\x01\xcd',
    b'\xcd\xc2', b'\xcc\xcd', b'\xcd\x0e', b'\x98\xcd',
    b'\xcdZ', b'T\xcd', b'\xcd\x96', b'h\xcd', b'\xcd\xaa',
    b'\xa4\xcd', b'\xcdf', b'\xf0\xcd', b'\xcd2', b'<\xcd',
    b'\xcd\xfe', b'\x01\x0f', b'\x0f\xc2', b'\xcc\x0f',
    b'\x0f\x0e', b'\x98\x0f', b'\x0fZ', b'T\x0f', b'\x0f\x96',
    b'h\x0f', b'\x0f\xaa', b'\xa4\x0f', b'\x0ff', b'\xf0\x0f',
    b'\x0f2', b'<\x0f', b'\x0f\xfe', b'\x01\x99', b'\x99\xc2',
    b'\xcc\x99', b'\x99\x0e', b'\x98\x99', b'\x99Z', b'T\x99',
    b'\x99\x96', b'h\x99', b'\x99\xaa', b'\xa4\x99', b'\x99f',
    b'\xf0\x99', b'\x992', b'<\x99', b'\x99\xfe', b'\x01[',
    b'[\xc2', b'\xcc[', b'[\x0e', b'\x98[', b'[Z', b'T[',
    b'[\x96', b'h[', b'[\xaa', b'\xa4[', b'[f', b'\xf0[',
    b'[2', b'<[', b'[\xfe', b'\x01U', b'U\xc2', b'\xccU',
    b'U\x0e', b'\x98U', b'UZ', b'TU', b'U\x96', b'hU', b'U\xaa',
    b'\xa4U', b'Uf', b'\xf0U', b'U2', b'<U', b'U\xfe',
    b'\x01\x97', b'\x97\xc2', b'\xcc\x97', b'\x97\x0e',
    b'\x98\x97', b'\x97Z', b'T\x97', b'\x97\x96', b'h\x97',
    b'\x97\xaa', b'\xa4\x97', b'\x97f', b'\xf0\x97', b'\x972',
    b'<\x97', b'\x97\xfe', b'\x01i', b'i\xc2', b'\xcci',
    b'i\x0e', b'\x98i', b'iZ', b'Ti', b'i\x96', b'hi', b'i\xaa',
    b'\xa4i', b'if', b'\xf0i', b'i2', b'<i', b'i\xfe',
    b'\x01\xab', b'\xab\xc2', b'\xcc\xab', b'\xab\x0e',
    b'\x98\xab', b'\xabZ', b'T\xab', b'\xab\x96', b'h\xab',
    b'\xab\xaa', b'\xa4\xab', b'\xabf', b'\xf0\xab', b'\xab2',
    b'<\xab', b'\xab\xfe', b'\x01\xa5', b'\xa5\xc2',
    b'\xcc\xa5', b'\xa5\x0e', b'\x98\xa5', b'\xa5Z', b'T\xa5',
    b'\xa5\x96', b'h\xa5', b'\xa5\xaa', b'\xa4\xa5', b'\xa5f',
    b'\xf0\xa5', b'\xa52', b'<\xa5', b'\xa5\xfe', b'\x01g',
    b'g\xc2', b'\xccg', b'g\x0e', b'\x98g', b'gZ', b'Tg',
    b'g\x96', b'hg', b'g\xaa', b'\xa4g', b'gf', b'\xf0g', b'g2',
    b'<g', b'g\xfe', b'\x01\xf1', b'\xf1\xc2', b'\xcc\xf1',
    b'\xf1\x0e', b'\x98\xf1', b'\xf1Z', b'T\xf1', b'\xf1\x96',
    b'h\xf1', b'\xf1\xaa', b'\xa4\xf1', b'\xf1f', b'\xf0\xf1',
    b'\xf12', b'<\xf1', b'\xf1\xfe', b'\x013', b'3\xc2',
    b'\xcc3', b'3\x0e', b'\x983', b'3Z', b'T3', b'3\x96', b'h3',
    b'3\xaa', b'\xa43', b'3f', b'\xf03', b'32', b'<3', b'3\xfe',
    b'\x01=', b'=\xc2', b'\xcc=', b'=\x0e', b'\x98=', b'=Z',
    b'T=', b'=\x96', b'h=', b'=\xaa', b'\xa4=', b'=f', b'\xf0=',
    b'=2', b'<=', b'=\xfe', b'\x01\xff', b'\xff\xc2',
    b'\xcc\xff', b'\xff\x0e', b'\x98\xff', b'\xffZ', b'T\xff',
    b'\xff\x96', b'h\xff', b'\xff\xaa', b'\xa4\xff', b'\xfff',
    b'\xf0\xff', b'\xff2', b'<\xff', b'\xff\xfe'
]

odds = [
    b'\x00\x01', b'\xc2\x00', b'\x00\xcc', b'\x0e\x00',
    b'\x00\x98', b'Z\x00', b'\x00T', b'\x96\x00', b'\x00h',
    b'\xaa\x00', b'\x00\xa4', b'f\x00', b'\x00\xf0', b'2\x00',
    b'\x00<', b'\xfe\x00', b'\xc3\x01', b'\xc2\xc3',
    b'\xc3\xcc', b'\x0e\xc3', b'\xc3\x98', b'Z\xc3', b'\xc3T',
    b'\x96\xc3', b'\xc3h', b'\xaa\xc3', b'\xc3\xa4', b'f\xc3',
    b'\xc3\xf0', b'2\xc3', b'\xc3<', b'\xfe\xc3', b'\xcd\x01',
    b'\xc2\xcd', b'\xcd\xcc', b'\x0e\xcd', b'\xcd\x98',
    b'Z\xcd', b'\xcdT', b'\x96\xcd', b'\xcdh', b'\xaa\xcd',
    b'\xcd\xa4', b'f\xcd', b'\xcd\xf0', b'2\xcd', b'\xcd<',
    b'\xfe\xcd', b'\x0f\x01', b'\xc2\x0f', b'\x0f\xcc',
    b'\x0e\x0f', b'\x0f\x98', b'Z\x0f', b'\x0fT', b'\x96\x0f',
    b'\x0fh', b'\xaa\x0f', b'\x0f\xa4', b'f\x0f', b'\x0f\xf0',
    b'2\x0f', b'\x0f<', b'\xfe\x0f', b'\x99\x01', b'\xc2\x99',
    b'\x99\xcc', b'\x0e\x99', b'\x99\x98', b'Z\x99', b'\x99T',
    b'\x96\x99', b'\x99h', b'\xaa\x99', b'\x99\xa4', b'f\x99',
    b'\x99\xf0', b'2\x99', b'\x99<', b'\xfe\x99', b'[\x01',
    b'\xc2[', b'[\xcc', b'\x0e[', b'[\x98', b'Z[', b'[T',
    b'\x96[', b'[h', b'\xaa[', b'[\xa4', b'f[', b'[\xf0', b'2[',
    b'[<', b'\xfe[', b'U\x01', b'\xc2U', b'U\xcc', b'\x0eU',
    b'U\x98', b'ZU', b'UT', b'\x96U', b'Uh', b'\xaaU', b'U\xa4',
    b'fU', b'U\xf0', b'2U', b'U<', b'\xfeU', b'\x97\x01',
    b'\xc2\x97', b'\x97\xcc', b'\x0e\x97', b'\x97\x98',
    b'Z\x97', b'\x97T', b'\x96\x97', b'\x97h', b'\xaa\x97',
    b'\x97\xa4', b'f\x97', b'\x97\xf0', b'2\x97', b'\x97<',
    b'\xfe\x97', b'i\x01', b'\xc2i', b'i\xcc', b'\x0ei',
    b'i\x98', b'Zi', b'iT', b'\x96i', b'ih', b'\xaai', b'i\xa4',
    b'fi', b'i\xf0', b'2i', b'i<', b'\xfei', b'\xab\x01',
    b'\xc2\xab', b'\xab\xcc', b'\x0e\xab', b'\xab\x98',
    b'Z\xab', b'\xabT', b'\x96\xab', b'\xabh', b'\xaa\xab',
    b'\xab\xa4', b'f\xab', b'\xab\xf0', b'2\xab', b'\xab<',
    b'\xfe\xab', b'\xa5\x01', b'\xc2\xa5', b'\xa5\xcc',
    b'\x0e\xa5', b'\xa5\x98', b'Z\xa5', b'\xa5T', b'\x96\xa5',
    b'\xa5h', b'\xaa\xa5', b'\xa5\xa4', b'f\xa5', b'\xa5\xf0',
    b'2\xa5', b'\xa5<', b'\xfe\xa5', b'g\x01', b'\xc2g',
    b'g\xcc', b'\x0eg', b'g\x98', b'Zg', b'gT', b'\x96g', b'gh',
    b'\xaag', b'g\xa4', b'fg', b'g\xf0', b'2g', b'g<', b'\xfeg',
    b'\xf1\x01', b'\xc2\xf1', b'\xf1\xcc', b'\x0e\xf1',
    b'\xf1\x98', b'Z\xf1', b'\xf1T', b'\x96\xf1', b'\xf1h',
    b'\xaa\xf1', b'\xf1\xa4', b'f\xf1', b'\xf1\xf0', b'2\xf1',
    b'\xf1<', b'\xfe\xf1', b'3\x01', b'\xc23', b'3\xcc',
    b'\x0e3', b'3\x98', b'Z3', b'3T', b'\x963', b'3h', b'\xaa3',
    b'3\xa4', b'f3', b'3\xf0', b'23', b'3<', b'\xfe3', b'=\x01',
    b'\xc2=', b'=\xcc', b'\x0e=', b'=\x98', b'Z=', b'=T',
    b'\x96=', b'=h', b'\xaa=', b'=\xa4', b'f=', b'=\xf0', b'2=',
    b'=<', b'\xfe=', b'\xff\x01', b'\xc2\xff', b'\xff\xcc',
    b'\x0e\xff', b'\xff\x98', b'Z\xff', b'\xffT', b'\x96\xff',
    b'\xffh', b'\xaa\xff', b'\xff\xa4', b'f\xff', b'\xff\xf0',
    b'2\xff', b'\xff<', b'\xfe\xff'
]

charmap = bytes(range(256)) * 2

table = {pair: charmap[i] for i, pair in enumerate(evens + odds)}


def conv(s):
    half = len(s)//2
    return map(bytes, zip(s[:half][::-1], s[half:]))


def decode(s):
    ret = b''

    for i, pair in enumerate(conv(s)):
        byte = table.get(pair, None)

        if byte is None:
            byte = table.get(pair[::-1], None)

        byte = bytes([byte]) if byte else bytes([pair[0]])

    return ret


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        out = decode(f.read())

    with open('out', 'wb') as f:
        f.write(out)
```
