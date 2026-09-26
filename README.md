# BabyCrackme (Challenge1) — Writeup

Sep 26, 2026 · @Mr.Empty

## TL;DR

Password đúng là `y0u_4r3_ju5t_t00_g00d_t0_b3_tru3` (32 ký tự). Nhập vào thì chương trình tự giải `flag.png.enc` ra `flag.png`.

Hàm check không băm hay mã hóa gì: nó chỉ xáo bit theo đường chéo trong từng block 8 byte (diagonal bit permutation), rồi so với một blob 32 byte hardcoded. Phép này là hoán vị bit nên đảo ngược thẳng được, không cần brute force hay z3. Phần AES-256-CBC qua bcrypt chỉ là mồi nhử.

## Challenge overview

Đề cho hai file và một yêu cầu: tìm password để chương trình tự giải ra ảnh flag.

| File | Kích thước | Mô tả |
| --- | --- | --- |
| `chall.exe` | 31 KB | PE x64, viết bằng C++ |
| `flag.png.enc` | 1428 KB | Ảnh flag đã mã hóa |

Khi chạy, chương trình hỏi password. Nhập đúng thì nó đọc `flag.png.enc`, giải mã rồi ghi ra `flag.png`. Nhập sai thì in `[-] Incorrect`.

Công cụ dùng: x64dbg để debug động, Python để dựng lại và đảo ngược thuật toán.

## Recon và anti-analysis

Logic thật của chương trình không nằm trong file PE mà được giải ra heap lúc runtime. Vì vậy phân tích tĩnh gần như không thấy gì.

- **Self-modifying entry point:** stub ở entry chạy một vòng XOR để giải mã code ra một vùng heap có quyền RWX, rồi nhảy vào đó.
- **Địa chỉ đổi mỗi lần chạy:** do heap chịu ASLR, không thể đặt breakpoint cố định theo module. Tuy nhiên offset nội bộ giữa các hàm thì không đổi.

### Cách lấy base của code trên heap

1. Nhấn F9 cho tới khi dừng ở `bcrypt!BCryptGenerateSymmetricKey`. Lúc này stub đã giải mã xong code.
2. Mở tab Call Stack. Cột **To** ở dòng đầu cho biết địa chỉ trả về trong code chall, có đuôi `...1C19`.
3. Tính `base = địa chỉ đó − 0x1C19`.

Các offset quan trọng tính từ `base`:

| Offset | Nội dung |
| --- | --- |
| `+0x1C19` | Return address sau lời gọi `BCryptGenerateSymmetricKey` |
| `+0x3380` | Hàm compare/transform |
| `+0x2532` | `cmp eax, 1` (EAX=1 nghĩa là đúng) |
| `+0x2535` | `jne` sang nhánh Incorrect (`0F 85`, 6 byte) |
| `+0x253B` | Nhánh Correct: `CreateFileA` → `ReadFile` → giải mã → `WriteFile` |
| `+0x25C3` | Nhánh Incorrect: in `[-] Incorrect` |

Vì code nằm ở vùng tự sinh, nếu bp phần mềm (`0xCC`) bị ghi đè hoặc vướng checksum thì dùng hardware bp: `bph base+3380, x`.

## Red herring: AES và patch nhánh

Có hai hướng trông rất hứa hẹn nhưng đều không dẫn tới flag.

### AES-256-CBC qua bcrypt

Chương trình gọi `BCryptGenerateSymmetricKey` 1 lần và `BCryptDecrypt` 2 lần, mỗi lần 48 byte. Key và IV đều hardcoded, không phụ thuộc password hay lần chạy:

- KEY: `D8 69 DE 8A E0 D0 A0 4C 3E 20 28 09 97 3C 9E 87 5F A7 2F 61 C0 0C 46 FB F3 B1 FE 5B A9 CC DA E6`
- IV: `89 EA 00 0C E0 89 7C E7 F7 F1 0C 6B 31 EB 9C A6`

Hai lần giải 48 byte này chỉ phục vụ việc check nội bộ lúc khởi tạo. File `flag.png.enc` **không** đi qua `BCryptDecrypt`. Có thể kiểm chứng bằng bp ở `CreateFileA`, `ReadFile` và `WriteFile`: với pass sai, cả ba đều có Hits = 0.

### Ép EAX=1 tại `cmp`

Sửa EAX thành 1 tại `base+2532` thì qua được `jne` và vào nhánh Correct. `CreateFileA("flag.png.enc")` có hit, nhưng `flag.png` sinh ra chỉ **0 KB**: routine giải mã bỏ dở trước khi `WriteFile`.

Điều này cho thấy nhánh giải file dùng chính password, hoặc dữ liệu dẫn xuất từ nó. Patch cờ không thay được dữ liệu đúng, nên phải reverse hàm compare để tìm password thật.

## Reverse hàm compare (`base+0x3380`)

Hàm này biến đổi password rồi so với một blob 32 byte hardcoded. Phép biến đổi là hoán vị bit theo đường chéo trong từng block 8 byte. RSI trỏ tới password người dùng nhập.

Blob đích:

```
33 53 74 39 79 16 74 7F  7C 30 53 71 7C 25 36 74
74 2D 33 56 7C 70 01 76  71 17 72 77 7B 72 04 7F
```

Blob chứa byte điều khiển như `0x16` và `0x01`, nên đây là output sau biến đổi chứ không phải password thô.

### Vòng lặp lõi

```asm
and  rcx, 7          ; index = (k + i) & 7, xoay vòng trong block 8 byte
mov  al, [rsi+rcx]   ; lấy pass[block + index]
and  rax, r8         ; giữ lại đúng 1 bit theo mask
or   rdx, rax        ; gom bit vào byte output
shr  r8, 1           ; mask: 0x80 → 0x40 → ... → 0x01
```

Pseudo-code tương đương:

```c
for (b = 0; b < 32; b += 8)
  for (k = 0; k < 8; k++) {
    out = 0; mask = 0x80;
    for (i = 0; i < 8; i++) {
      out |= pass[b + ((k + i) & 7)] & mask;
      mask >>= 1;
    }
    result[b + k] = out;
  }
return memcmp(result, blob, 32) == 0;
```

### Ý nghĩa: đọc ma trận bit theo đường chéo

Coi mỗi block 8 byte là một ma trận bit 8×8, mỗi hàng là một ký tự. Output byte `k` lấy bit 7 từ hàng `k`, bit 6 từ hàng `k+1`, bit 5 từ hàng `k+2`, cứ thế quay vòng mod 8.

Điểm then chốt là bit **giữ nguyên cột**: code không có `shl`/`shr` nào trên `al`, chỉ có mask trượt. Mỗi bit input đi tới đúng một bit output, không bit nào bị gộp hay mất. Vì vậy phép này khả nghịch hoàn toàn.

Dấu hiệu phụ: bit 7 của output luôn lấy từ `pass[k]`. Password ASCII có bit 7 = 0, và quả thật mọi byte blob đều nhỏ hơn `0x80`.

### Tính tay `out[0]` của block đầu

Block đầu của password là `y0u_4r3_`:

| i | mask | Byte nguồn | byte & mask |
| --- | --- | --- | --- |
| 0 | 0x80 | `y` 0x79 | 0x00 |
| 1 | 0x40 | `0` 0x30 | 0x00 |
| 2 | 0x20 | `u` 0x75 | 0x20 |
| 3 | 0x10 | `_` 0x5F | 0x10 |
| 4 | 0x08 | `4` 0x34 | 0x00 |
| 5 | 0x04 | `r` 0x72 | 0x00 |
| 6 | 0x02 | `3` 0x33 | 0x02 |
| 7 | 0x01 | `_` 0x5F | 0x01 |

OR các cột cuối: `0x20 | 0x10 | 0x02 | 0x01 = 0x33`, đúng bằng byte đầu của blob.

### Loại trừ các biến thể

5 lệnh trên chưa chốt được chiều xoay và chiều mask, nên đã thử cả bốn tổ hợp cùng với phép bit-transpose 8×8:

| Biến thể | Kết quả đảo ngược |
| --- | --- |
| `(k+i)`, mask `0x80>>i` | `y0u_4r3_ju5t_t00_g00d_t0_b3_tru3` |
| `(k-i)`, mask `1<<i` | `_y0u_4r30ju5t_...` (lệch 1 ký tự) |
| Hai tổ hợp còn lại | Rác, có byte không in được |
| Bit-transpose 8×8 | Rác, có byte ≥ 0x80 |

Chỉ một biến thể ra câu leet-speak có nghĩa, và khi chạy chiều thuận thì khớp đủ 32 byte blob.

## Solve script

Script đảo ngược blob về password, rồi chạy chiều thuận để kiểm tra lại. Công thức đảo: bit `(7-i)` của `pass[(k+i)&7]` bằng bit `(7-i)` của `out[k]`.

```python
blob = bytes.fromhex(
    "335374397916747f7c3053717c253674"
    "742d33567c700176711772777b72047f"
)

def transform(p):
    """Chiều thuận, giống hàm base+0x3380."""
    out = bytearray()
    for b in range(0, 32, 8):
        for k in range(8):
            d = 0
            for i in range(8):
                d |= p[b + ((k + i) & 7)] & (0x80 >> i)
            out.append(d)
    return bytes(out)

def invert(out):
    """Đưa từng bit về đúng byte nguồn, giữ nguyên vị trí cột."""
    res = bytearray(32)
    for b in range(0, 32, 8):
        for k in range(8):
            for i in range(8):
                m = 0x80 >> i
                if out[b + k] & m:
                    res[b + ((k + i) & 7)] |= m
    return bytes(res)

pw = invert(blob)
print(pw.decode())             # y0u_4r3_ju5t_t00_g00d_t0_b3_tru3
assert transform(pw) == blob   # khớp đủ 32 byte
```

## Verify trong x64dbg và lấy flag

Với password đúng, EAX tự bằng 1 tại `cmp`, không cần patch gì. Các bước kiểm tra:

1. Nhấn F9 tới `BCryptGenerateSymmetricKey` và tính `base` như phần Recon.
2. Đặt bp ở đầu hàm compare bằng lệnh `bp base+3380`, hoặc `bph base+3380, x` nếu bp phần mềm bị ghi đè.
3. Nhấn F9 rồi nhập password. Khi dừng, chạy `d rsi`: tab Dump phải hiện `y0u_4r3_ju5t_...`.
4. Nhấn Ctrl+F9 để chạy tới `ret`, rồi F8 về caller. Tại `base+2532`, EAX phải bằng `1`.
5. Tùy chọn: đặt bp ở `WriteFile` rồi `d rdx`, sẽ thấy PNG magic `89 50 4E 47 0D 0A 1A 0A`.
6. Xóa hết breakpoint (tab Breakpoints, chọn tất cả, nhấn Delete) và chạy lại một mạch. Chương trình sẽ ghi `flag.png` đầy đủ, flag nằm trong ảnh.

Nếu muốn log toàn bộ vòng lặp để đối chiếu, vào Trace → Trace into... (Ctrl+Alt+F7). Log Text đặt là `{p:cip} {i:cip} rcx={rcx} rdx={rdx} r8={r8}`, Break Condition đặt là `cip == <địa chỉ ret của hàm>`, rồi chọn một Log File.

## Bài học rút ra

- **Crypto API bắt mắt chưa chắc là đường tới flag.** Cần đặt bp ở tầng I/O (`CreateFileA`/`ReadFile`/`WriteFile`) để biết dữ liệu thật đi qua đâu.
- **Patch nhánh chỉ hiệu quả khi dữ liệu phía sau không phụ thuộc input.** File ra 0 KB là tín hiệu nhánh Correct cần password thật.
- **Nhận diện hoán vị bit qua pattern lệnh.** Chỉ có `and`/`or` cùng một mask trượt, không dịch dữ liệu, thì gần như chắc là permutation. Khi đó đảo trực tiếp, chưa cần tới brute force hay z3.
- **Ép giả thuyết qua phép thử chiều thuận.** Output đọc được là gợi ý tốt, nhưng khớp đủ 32 byte blob mới là bằng chứng.
