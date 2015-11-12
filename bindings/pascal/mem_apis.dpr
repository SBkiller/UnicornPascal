{
  Pascal/Delphi bindings for the UnicornEngine Emulator Engine

  Copyright(c) 2015 Stefan Ascher

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
}

program mem_apis;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
  {$apptype CONSOLE}
  {$R *.res}
{$endif}

uses
  SysUtils, Unicorn, UnicornConst;

var
  insts_executed: integer;

procedure HookCode(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
var
  opcode: UInt8;
  buf: array[0..255] of Byte;
begin
  Inc(insts_executed);

  if (uc_mem_read_(uc, address, @buf, size) <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - uc_mem_read fail during hook_code callback, addr: 0x%x', [address]));
    if uc_emu_stop(uc) <> UC_ERR_OK then begin
      WriteLn(Format('not ok - uc_emu_stop fail during hook_code callback, addr: 0x%x', [address]));
      Halt(1);
    end;
  end;

  opcode := buf[0];
  case opcode of
    $41:
      begin
        // inc ecx
        if (uc_mem_protect(uc, $101000, $1000, UC_PROT_READ) <> UC_ERR_OK) then begin
          WriteLn(Format('not ok - uc_mem_protect fail during hook_code callback, addr: 0x%x', [address]));
          Halt(1);
        end;
      end;
    $42:
      begin
        // inc edx
        if (uc_mem_unmap(uc, $101000, $1000) <> UC_ERR_OK) then begin
          WriteLn(Format('not ok - uc_mem_unmap fail during hook_code callback, addr: 0x%x', [address]));
          Halt(1);
        end;
      end;
    $f4:
      begin
        // hlt
        if (uc_emu_stop(uc) <> UC_ERR_OK) then begin
          WriteLn(Format('not ok - uc_emu_stop fail during hook_code callback, addr: 0x%x', [address]));
          Halt(1);
        end;
      end;
    else
      begin
        // all others...
      end;
  end;
end;

function HookMemInvalid(uc: uc_engine; _type: uc_mem_type; address: UInt64;
  size: Cardinal; value: Int64; user_data: Pointer): LongBool; cdecl;
begin
  case _type of
    UC_MEM_READ_UNMAPPED:
      begin
        WriteLn(Format('not ok - Read from invalid memory at 0x%x, data size = %u', [address, size]));
        Result := false;
      end;
    UC_MEM_WRITE_UNMAPPED:
      begin
        WriteLn(Format('not ok - Write to invalid memory at 0x%x, data size = %u, data value = 0x%x', [address, size, value]));
        Result := false;
      end;
    UC_MEM_FETCH_PROT:
      begin
        WriteLn(Format('not ok - Fetch from non-executable memory at 0x%x', [address]));
        Result := false;
      end;
    UC_MEM_WRITE_PROT:
      begin
        WriteLn(Format('not ok - Write to non-writeable memory at 0x%x, data size = %u, data value = 0x%x', [address, size, value]));
        Result := false;
      end;
    else
      begin
        WriteLn(Format('not ok - UC_HOOK_MEM_INVALID type: %d at 0x%x', [_type, address]));
        Result := false;
      end;
  end;
end;

procedure DoNxDemo(cause_fault: boolean);
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  code_buf: array[0..$3000-1] of Byte;
const
  IS_FAULTING: array[boolean] of string = ('non-faulting', 'faulting');
  JUMP_TO_102000: array[0..5] of Byte = ($e9, $00, $10, $00, $00, $00);         // jump to 0x102000
  JUMP_TO_101000: array[0..5] of Byte = ($e9, $fb, $ef, $ff, $ff, $00);         // jump to 0x101000
begin
  insts_executed := 0;
  WriteLn('===================================');
  WriteLn(Format('# Example of marking memory NX (%s)', [IS_FAULTING[cause_fault]]));

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  uc_mem_map(uc, $100000, $3000, UC_PROT_READ or UC_PROT_EXEC);
  (*
     bits 32
  page0:
      times 4091 inc eax
      jmp page2
      page1:
      times 4095 inc eax
      hlt
  page2:
      jmp page1
  *)
  // fill with inc eax
  FillChar(code_buf, SizeOf(code_buf), $40);
  Move(JUMP_TO_102000, code_buf[$1000 - 5], 5);
  Move(JUMP_TO_101000, code_buf[$2000], 5);
  code_buf[$1fff] := $f4;  // hlt

  if (cause_fault) then
    // insert instruction to trigger U_PROT_EXEC change (see hook_code function)
    code_buf[$1000] := $41;     // inc ecx at page1

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, $100000, @code_buf, SizeOf(code_buf)) <> UC_ERR_OK) then begin
    WriteLn('not ok - Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // intercept code and invalid memory events
  if ((uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0) <> UC_ERR_OK) or
    (uc_hook_add(uc, trace1, UC_HOOK_MEM_INVALID, @HookMemInvalid, nil) <> UC_ERR_OK)) then begin
    WriteLn('not ok - Failed to install hooks');
    Exit;
  end;

  // emulate machine code until told to stop by HookCode
  WriteLn('BEGINNING EXECUTION');
  err := uc_emu_start(uc, $100000, $103000, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failure on uc_emu_start() with error %u: %s', [err, uc_strerror(err)]));
    WriteLn('FAILED EXECUTION');
  end else begin
    WriteLn('SUCCESSFUL EXECUTION');
  end;

  WriteLn(Format('Executed %d instructions', [insts_executed]));
  WriteLn;
  uc_close(uc);
end;

procedure NxTest;
begin
  WriteLn('NX demo - step 1: show that code runs to completion');
  DoNxDemo(false);
  WriteLn('NX demo - step 2: show that code fails without UC_PROT_EXEC');
  DoNxDemo(true);
end;

const
  WRITE_DEMO: array[0..31] of Byte = (
    $90, $c7, $05, $00, $20, $10, $00, $78, $56, $34, $12, $c7, $05, $fc, $0f, $10,
    $00, $78, $56, $34, $12, $c7, $05, $00, $10, $10, $00, $21, $43, $65, $87, $00);

procedure DoPermsDemo(change_perms: boolean);
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  code_buf: array[0..$3000-1] of Byte;
  pbuff: PByte;
begin
  insts_executed := 0;
  WriteLn('===================================');
  WriteLn('# Example of manipulating memory permissions');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  uc_mem_map(uc, $100000, $3000, UC_PROT_ALL);

  (*
     bits 32
     nop
     mov dword [0x102000], 0x12345678
     mov dword [0x100ffc], 0x12345678
     mov dword [0x101000], 0x87654321    ; crashing case crashes here
     times 1000 nop
     hlt
   *)
  Move(WRITE_DEMO, code_buf[0], SizeOf(WRITE_DEMO) - 1);
  pbuff := @code_buf[SizeOf(WRITE_DEMO) - 1];
  FillChar(pbuff^, 1000, $90);
  code_buf[SizeOf(WRITE_DEMO) - 1 + 1000] := $f4;  // hlt

  if (change_perms) then
    // write protect memory area [0x101000, 0x101fff]. see hook_code function
    code_buf[0] := $41;     // inc ecx

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, $100000, @code_buf, SizeOf(code_buf)) <> UC_ERR_OK) then begin
    WriteLn('not ok - Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // intercept code and invalid memory events
  if ((uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0) <> UC_ERR_OK) or
    (uc_hook_add(uc, trace1, UC_HOOK_MEM_INVALID, @HookMemInvalid, nil) <> UC_ERR_OK)) then begin
    WriteLn('not ok - Failed to install hooks');
    Exit;
  end;

  // emulate machine code until told to stop by hook_code
  WriteLn('BEGINNING EXECUTION');
  err := uc_emu_start(uc, $100000, $103000, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failure on uc_emu_start() with error %u: %s', [err, uc_strerror(err)]));
    WriteLn('FAILED EXECUTION');
  end else begin
    WriteLn('SUCCESSFUL EXECUTION');
  end;

  WriteLn(Format('Executed %d instructions', [insts_executed]));
  WriteLn;
  uc_close(uc);
end;

procedure PermsTest;
begin
  WriteLn('Permissions demo - step 1: show that area is writeable');
  DoPermsDemo(false);
  WriteLn('Permissions demo - step 2: show that code fails when memory marked unwriteable');
  DoPermsDemo(true);
end;

procedure DoUnmapDemo(do_unmap: boolean);
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  code_buf: array[0..$3000-1] of Byte;
  pbuff: PByte;
begin
  insts_executed := 0;
  WriteLn('===================================');
  WriteLn('# Example of unmapping memory');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  uc_mem_map(uc, $100000, $3000, UC_PROT_ALL);

  (*
     bits 32
     nop
     mov dword [0x102000], 0x12345678
     mov dword [0x100ffc], 0x12345678
     mov dword [0x101000], 0x87654321  ; crashing case crashes here
     times 1000 nop
     hlt
   *)
  Move(WRITE_DEMO, code_buf[0], SizeOf(WRITE_DEMO) - 1);
  pbuff := @code_buf[SizeOf(WRITE_DEMO) - 1];
  FillChar(pbuff^, 1000, $90);
  code_buf[SizeOf(WRITE_DEMO) - 1 + 1000] := $f4;  // hlt

  if (do_unmap) then
    // unmap memory area [0x101000, 0x101fff]. see hook_code function
    code_buf[0] := $42;    // inc edx  (see hook_code function)

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, $100000, @code_buf, $1000) <> UC_ERR_OK) then begin
    WriteLn('not ok - Failed to write emulation code to memory, quit!');
    Exit;
  end;

  if ((uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0) <> UC_ERR_OK) or
    (uc_hook_add(uc, trace1, UC_HOOK_MEM_INVALID, @HookMemInvalid, nil) <> UC_ERR_OK)) then begin
    WriteLn('not ok - Failed to install hooks');
    Exit;
  end;

  // emulate machine code until told to stop by hook_code
  WriteLn('BEGINNING EXECUTION');
  err := uc_emu_start(uc, $100000, $103000, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('not ok - Failure on uc_emu_start() with error %u: %s', [err, uc_strerror(err)]));
    WriteLn('FAILED EXECUTION');
  end else begin
    WriteLn('SUCCESSFUL EXECUTION');
  end;

  WriteLn(Format('Executed %d instructions', [insts_executed]));
  WriteLn;
  uc_close(uc);
end;

procedure UnmapText;
begin
  WriteLn('Unmap demo - step 1: show that area is writeable');
  DoUnmapDemo(false);
  WriteLn('Unmap demo - step 2: show that code fails when memory is unmapped');
  DoUnmapDemo(true);
end;

begin
  NxTest;
  PermsTest;
  UnmapText;
end.
