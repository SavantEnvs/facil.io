# fuzz_fiobj known findings (upstream bugs, left unfixed)

Each `.bin` replays with `/mayhem/fuzz_fiobj-standalone <file>`. The first byte picks a temp-file or in-memory data object; the rest is
an op stream (`byte % 28` selects the op, see `mayhem/fuzz_fiobj.c`).

## `ary-set-after-shift-oob-read.bin` — `fiobj_ary_set` then `fiobj_ary_shift`, `fio.h:5171` (`fio_ary___shift`)

The input pushes 12 empty strings, shifts 10, then calls `fiobj_ary_set(ary, num, 2)`, then shifts again.
`fio_ary___set` (the `FIO_ARY` template in `fio.h`) writes the new element at `arry + start + index` but stores `ary->end = index + 1`,
forgetting the `start` offset. After shifts `start > 0`, so `end` drops below `start`, `count()` (`end - start`) wraps to a huge
`size_t`, and every following `shift` walks `start` past the allocation: ASan heap-buffer-overflow READ of 8 bytes.
This is public API used in an ordinary order, not harness aliasing.
The `fio_ary___remove` and `fio_ary___each` out-of-bounds reads Mayhem also reports for this target reach the same corrupted
`start`/`end` state through other ops (`fio.h:5081` and `:5196`); they appear to share this root cause, but each was not
reproduced separately.
Fix: `ary->end = ary->start + index + 1;`.

## `str-self-concat-use-after-free.bin` — `fiobj_str_concat(str, str)`, `fio_str_write`

The harness (`case 19`) calls `fiobj_str_concat(str, str)` on a string holding 63 bytes. `fiobj_str_concat` takes the source pointer
with `fiobj_obj2cstr(obj)` and hands it to `fio_str_write`, which calls `fio_str_resize` (a `realloc` that moves the buffer) and then
`memcpy`s from the old, freed pointer: ASan heap-use-after-free READ.
Whether the source may alias the destination is the harness's choice here: the library does not document that `dest` and `obj` must
differ, and `fio_str_write` is also public, so I count it as a library bug, but it is the defect closest to harness-chosen aliasing.
Fix: in `fio_str_write`, if `src` points inside the string's current buffer, remember its offset and re-derive `src` from the
resized buffer before the `memcpy`.

## `fiobj-data-pread-exit.bin` — `fiobj_data_pread` on a file-backed object, `fiobj_data.c:882` / `:140`

Stack: `fiobj_data_pread` → `fiobj_data_pread_file` → `fiobj_data_pre_write` → `REQUIRE_MEM` → `exit(errno)`.
The length the harness passes is at most 255. The huge value comes from inside `fiobj_data_pread_file`: when `start_at` is beyond
the end of the file, `length = size - start_at` is negative and wraps to a huge `uintptr_t`; `fio_realloc` then fails and
`REQUIRE_MEM` calls `exit()` ("couldn't allocate memory"). A read past EOF should return an empty result.
Impact: any caller that reads at an offset past EOF exits the process.
Fix: `length = start_at >= size ? 0 : size - start_at;`.
