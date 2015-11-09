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

// Sample code to trace code with Linux code with syscall

program shellcode;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
	{$apptype CONSOLE}
	{$R *.res}
{$endif}

uses
  SysUtils, Math, Unicorn, UnicornConst, X86Const;

const
	// code to be emulated WITH terminating 0
	X86_CODE32: array[0..37] of Byte = (
  	$eb, $19, $31, $c0, $31, $db, $31, $d2, $31, $c9,
    $b0, $04, $b3, $01, $59, $b2, $05, $cd, $80, $31,
    $c0, $b0, $01, $31, $db, $cd, $80, $e8, $e2, $ff,
    $ff, $ff, $68, $65, $6c, $6c, $6f, $00);
  X86_CODE32_SELF: array[0..67] of Byte = (
  	$eb, $1c, $5a, $89, $d6, $8b, $02, $66, $3d, $ca,
    $7d, $75, $06, $66, $05, $03, $03, $89, $02, $fe,
    $c2, $3d, $41, $41, $41, $41, $75, $e9, $ff, $e6,
    $e8, $df, $ff, $ff, $ff, $31, $d2, $6a, $0b, $58,
    $99, $52, $68, $2f, $2f, $73, $68, $68, $2f, $62,
    $69, $6e, $89, $e3, $52, $53, $89, $e1, $ca, $7d,
    $41, $41, $41, $41, $41, $41, $41, $41);
	// memory address where emulation starts
	ADDRESS = $10000;

// callback for tracing instruction
procedure HookCode(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
var
	r_eip: integer;
  tmp: array[0..15] of UInt8;
  err: uc_err;
  i: integer;
begin
  WriteLn(Format('Tracing instruction at 0x%x, instruction size = 0x%x', [address, size]));

  uc_reg_read(uc, UC_X86_REG_EIP, @r_eip);
  Write(Format('*** EIP = %x ***: ', [r_eip]));

  size := Min(SizeOf(tmp), size);
  err := uc_mem_read_(uc, address, @tmp, size);
  if (err = UC_ERR_OK) then begin
    for i := 0 to size - 1 do begin
      Write(Format('%x', [tmp[i]]));
    end;
    WriteLn;
  end;
end;

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
procedure HookIntr(uc: uc_engine; intno: UInt32; user_data: Pointer); cdecl;
var
	r_eax, r_ecx, r_eip: integer;
  r_edx, size: UInt32;
  buffer: array[0..255] of Byte;
  err: uc_err;
  str_buffer: AnsiString;
begin
	// only handle Linux syscall
  if (intno <> $80) then
  	Exit;

  uc_reg_read(uc, UC_X86_REG_EAX, @r_eax);
  uc_reg_read(uc, UC_X86_REG_EIP, @r_eip);

  case r_eax of
  	1:
    	begin
        // sys_exit
        WriteLn(Format('>>> 0x%x: interrupt 0x%x, SYS_EXIT. quit!', [r_eip, intno]));
        uc_emu_stop(uc);
      end;
    4:
    	begin
        // sys_write
        // ECX = buffer address
			  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
        // EDX = buffer size
			  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
        // read the buffer in
        size := Min(SizeOf(buffer)-1, r_edx);
        err := uc_mem_read_(uc, r_ecx, @buffer, size);
        if (err = UC_ERR_OK) then begin
          buffer[size] := 0;
          str_buffer := StrPas(PAnsiChar(@buffer));
          WriteLn(Format('>>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = "%s"', [r_eip, intno, r_ecx, r_edx, str_buffer]));
        end else begin
          WriteLn(Format('>>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u (cannot get content)', [r_eip, intno, r_ecx, r_edx]));
        end;
      end;
    else
    	begin
        WriteLn(Format('>>> 0x%x: interrupt 0x%x, EAX = 0x%x', [r_eip, intno, r_eax]));
      end;
  end;
end;

procedure TestI386;
var
	uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  r_esp: integer;
begin
	r_esp := ADDRESS + $200000;

  WriteLn('Emulate i386 code');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
  	WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_SELF, SizeOf(X86_CODE32_SELF) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ESP, @r_esp);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace1, UC_HOOK_CODE, @HookCode, nil, 1, 0);

  // handle interrupt ourself
  uc_hook_add(uc, trace2, UC_HOOK_INTR, @HookIntr, nil);

  WriteLn;
  WriteLn('>>> Start tracing this Linux code');

  // emulate machine code in infinite time
  // err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF), 0, 12); <--- emulate only 12 instructions
  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_SELF) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  WriteLn;
  WriteLn('>>> Emulation done.');

  uc_close(uc);
end;

begin
	if ParamCount > 0 then begin
    if (ParamStr(1) = '-32') then begin
      TestI386;
    end;
  end else
  	WriteLn('Syntax: shellcode <-32|-64>');
end.
